/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.eltavine.duckdetector.features.dangerousapps.data.repository

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.os.Parcel
import android.provider.Settings
import android.text.TextUtils
import com.eltavine.duckdetector.capability.packageinventory.data.AndroidInstalledPackageInventoryReader
import com.eltavine.duckdetector.capability.packageinventory.data.PackageDataDirectoryProbe
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageInventoryReader
import com.eltavine.duckdetector.features.dangerousapps.data.probes.CreatePackageContextZipProbe
import com.eltavine.duckdetector.features.dangerousapps.data.probes.OpenApkFdPackageProbe
import com.eltavine.duckdetector.features.dangerousapps.data.probes.SceneDebugfsContextProbe
import com.eltavine.duckdetector.features.dangerousapps.data.probes.SceneLoopbackProbe
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppFinding
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppTarget
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsCatalog
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsReport
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsStage
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousDetectionMethod
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousDetectionMethodKind
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousPackageVisibility
import java.io.File
import kotlin.random.Random
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class DangerousAppsRepository(
    private val context: Context,
    private val packageInventoryReader: InstalledPackageInventoryReader =
        AndroidInstalledPackageInventoryReader(context.applicationContext),
    private val nativeBridge: PackageDataDirectoryProbe = PackageDataDirectoryProbe(),
    private val createPackageContextZipProbe: CreatePackageContextZipProbe =
        CreatePackageContextZipProbe(context),
    private val openApkFdPackageProbe: OpenApkFdPackageProbe = OpenApkFdPackageProbe(),
    private val sceneDebugfsContextProbe: SceneDebugfsContextProbe = SceneDebugfsContextProbe(),
    private val sceneLoopbackProbe: SceneLoopbackProbe = SceneLoopbackProbe(),
) {
    suspend fun scan(): DangerousAppsReport = withContext(Dispatchers.IO) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                DangerousAppsReport.failed(
                    targets = DangerousAppsCatalog.targets,
                    message = throwable.message ?: "Dangerous app scan failed.",
                )
            }
    }

    private fun scanInternal(): DangerousAppsReport {
        val targets = DangerousAppsCatalog.targets
        val detectedApps = linkedMapOf<String, MutableFinding>()
        val issues = mutableListOf<String>()

        val packageInventory = PackageVisibilityChecker.inspect(packageInventoryReader)
        val installedPackages = packageInventory.packageNames
        val packageManagerVisibleCount = installedPackages.size
        val packageVisibility = packageInventory.visibility
        val suspiciousLowPmInventory = packageInventory.suspiciouslyLow
        val suspiciousSharedStorageDenied = detectSharedStorageBaselineDenied()

        if (packageVisibility == DangerousPackageVisibility.RESTRICTED) {
            issues += "PackageManager visibility is restricted on this device profile."
        }
        packageInventory.issue?.let(issues::add)
        if (suspiciousLowPmInventory) {
            issues += "PackageManager returned only $packageManagerVisibleCount visible packages despite a full inventory result. This can happen under HMA-style whitelist filtering."
        }
        if (suspiciousSharedStorageDenied) {
            issues += "Shared external-storage baseline paths all returned EACCES/EPERM. This suggests shared user gid or related zygote storage groups may have been restricted."
        }

        if (packageVisibility == DangerousPackageVisibility.FULL) {
            targets.forEach { target ->
                if (target.packageName in installedPackages) {
                    appendMethod(
                        detectedApps = detectedApps,
                        target = target,
                        method = DangerousDetectionMethod(DangerousDetectionMethodKind.PACKAGE_MANAGER),
                    )
                }
            }
        }

        createPackageContextZipProbe
            .run(targets.mapTo(linkedSetOf()) { it.packageName })
            .detectedPackages
            .forEach { packageName ->
                appendMethod(
                    detectedApps = detectedApps,
                    packageName = packageName,
                    method = DangerousDetectionMethod(
                        DangerousDetectionMethodKind.CREATE_PACKAGE_CONTEXT_ZIP,
                    ),
                )
            }

        openApkFdPackageProbe
            .run(targets.mapTo(linkedSetOf()) { it.packageName })
            .detectedPackages
            .forEach { packageName ->
                appendMethod(
                    detectedApps = detectedApps,
                    packageName = packageName,
                    method = DangerousDetectionMethod(DangerousDetectionMethodKind.OPEN_APK_FD),
                )
            }

        enumerateAndroidDirsByListing().forEach { packageName ->
            appendMethod(
                detectedApps = detectedApps,
                packageName = packageName,
                method = DangerousDetectionMethod(DangerousDetectionMethodKind.DIRECTORY_LISTING),
            )
        }

        enumerateAndroidDirsByZeroWidthBypass().forEach { packageName ->
            appendMethod(
                detectedApps = detectedApps,
                packageName = packageName,
                method = DangerousDetectionMethod(DangerousDetectionMethodKind.ZWC_BYPASS),
            )
        }

        enumerateAndroidDirsByIgnorableCodePoints().forEach { packageName ->
            appendMethod(
                detectedApps = detectedApps,
                packageName = packageName,
                method = DangerousDetectionMethod(DangerousDetectionMethodKind.IGNORABLE_CODEPOINT_BYPASS),
            )
        }

        targets.forEach { target ->
            if (checkFuseDataPath(target.packageName)) {
                appendMethod(
                    detectedApps = detectedApps,
                    target = target,
                    method = DangerousDetectionMethod(DangerousDetectionMethodKind.FUSE_STAT),
                )
            }
        }

        nativeBridge.statPackages(targets.map { it.packageName }).forEach { packageName ->
            appendMethod(
                detectedApps = detectedApps,
                packageName = packageName,
                method = DangerousDetectionMethod(DangerousDetectionMethodKind.NATIVE_DATA_STAT),
            )
        }

        DangerousAppsCatalog.specialPathDetection.forEach { (path, packageName) ->
            if (checkPathExists(path)) {
                appendMethod(
                    detectedApps = detectedApps,
                    packageName = packageName,
                    method = DangerousDetectionMethod(
                        kind = DangerousDetectionMethodKind.SPECIAL_PATH,
                        detail = path,
                        hmaEligible = path !in DangerousAppsCatalog.excludedPathsForHmaInference,
                    ),
                )
            }
        }

        if (detectThanoxIpc()) {
            appendMethod(
                detectedApps = detectedApps,
                packageName = THANOX_PACKAGE,
                method = DangerousDetectionMethod(DangerousDetectionMethodKind.THANOX_IPC),
            )
        }

        if (isAccessibilityServiceEnabled(SCENE_PACKAGE)) {
            appendMethod(
                detectedApps = detectedApps,
                packageName = SCENE_PACKAGE,
                method = DangerousDetectionMethod(DangerousDetectionMethodKind.ACCESSIBILITY_SERVICE),
            )
        }

        sceneLoopbackProbe.probe()
            .takeIf { it.detected }
            ?.let { result ->
                appendMethod(
                    detectedApps = detectedApps,
                    packageName = SCENE_PACKAGE,
                    method = DangerousDetectionMethod(
                        kind = DangerousDetectionMethodKind.SCENE_LOOPBACK,
                        detail = result.detail,
                    ),
                )
            }

        detectSceneDebugfsMount()?.let { markerPath ->
            appendMethod(
                detectedApps = detectedApps,
                packageName = SCENE_PACKAGE,
                method = DangerousDetectionMethod(
                    kind = DangerousDetectionMethodKind.SPECIAL_PATH,
                    detail = markerPath,
                ),
            )
        }

        sceneDebugfsContextProbe.probe()
            .takeIf { it.detected }
            ?.let { result ->
                appendMethod(
                    detectedApps = detectedApps,
                    packageName = SCENE_PACKAGE,
                    method = DangerousDetectionMethod(
                        kind = DangerousDetectionMethodKind.SCENE_DEBUGFS_CONTEXT,
                        detail = result.detail,
                    ),
                )
            }

        if (detectSceneBroadcast()) {
            appendMethod(
                detectedApps = detectedApps,
                packageName = SCENE_PACKAGE,
                method = DangerousDetectionMethod(DangerousDetectionMethodKind.SCENE_BROADCAST),
            )
        }

        val findings = buildFindings(detectedApps)
        val hiddenFromPackageManager = if (packageVisibility == DangerousPackageVisibility.FULL) {
            findings.filter { finding ->
                finding.target.packageName !in installedPackages &&
                        finding.methods.any { it.kind != DangerousDetectionMethodKind.PACKAGE_MANAGER && it.hmaEligible }
            }
        } else {
            emptyList()
        }

        return DangerousAppsReport(
            stage = DangerousAppsStage.READY,
            packageVisibility = packageVisibility,
            packageManagerVisibleCount = packageManagerVisibleCount,
            suspiciousLowPmInventory = suspiciousLowPmInventory,
            suspiciousSharedStorageDenied = suspiciousSharedStorageDenied,
            targets = targets,
            findings = findings,
            hiddenFromPackageManager = hiddenFromPackageManager,
            probesRan = buildProbeList(packageVisibility),
            issues = issues,
        )
    }

    private fun buildFindings(
        detectedApps: Map<String, MutableFinding>,
    ): List<DangerousAppFinding> {
        return DangerousAppsCatalog.targets.mapNotNull { target ->
            detectedApps[target.packageName]?.let { finding ->
                DangerousAppFinding(
                    target = target,
                    methods = finding.methods.sortedWith(
                        compareBy<DangerousDetectionMethod>(
                            { it.kind.ordinal },
                            { it.displayText }),
                    ),
                )
            }
        }
    }

    private fun buildProbeList(
        packageVisibility: DangerousPackageVisibility,
    ): List<DangerousDetectionMethodKind> {
        return buildList {
            if (packageVisibility == DangerousPackageVisibility.FULL) {
                add(DangerousDetectionMethodKind.PACKAGE_MANAGER)
            }
            add(DangerousDetectionMethodKind.CREATE_PACKAGE_CONTEXT_ZIP)
            add(DangerousDetectionMethodKind.OPEN_APK_FD)
            add(DangerousDetectionMethodKind.DIRECTORY_LISTING)
            add(DangerousDetectionMethodKind.ZWC_BYPASS)
            add(DangerousDetectionMethodKind.IGNORABLE_CODEPOINT_BYPASS)
            add(DangerousDetectionMethodKind.FUSE_STAT)
            add(DangerousDetectionMethodKind.NATIVE_DATA_STAT)
            add(DangerousDetectionMethodKind.SPECIAL_PATH)
            add(DangerousDetectionMethodKind.SCENE_LOOPBACK)
            add(DangerousDetectionMethodKind.SCENE_DEBUGFS_CONTEXT)
            add(DangerousDetectionMethodKind.SCENE_BROADCAST)
            add(DangerousDetectionMethodKind.THANOX_IPC)
            add(DangerousDetectionMethodKind.ACCESSIBILITY_SERVICE)
        }
    }

    private fun appendMethod(
        detectedApps: MutableMap<String, MutableFinding>,
        target: DangerousAppTarget,
        method: DangerousDetectionMethod,
    ) {
        detectedApps
            .getOrPut(target.packageName) { MutableFinding(target) }
            .methods
            .add(method)
    }

    private fun appendMethod(
        detectedApps: MutableMap<String, MutableFinding>,
        packageName: String,
        method: DangerousDetectionMethod,
    ) {
        val target = DangerousAppsCatalog.targetByPackage[packageName] ?: return
        appendMethod(detectedApps, target, method)
    }

    @Suppress("PrivateApi")
    private fun detectThanoxIpc(): Boolean {
        var data: Parcel? = null
        var reply: Parcel? = null
        return try {
            val serviceManagerClass = Class.forName("android.os.ServiceManager")
            val getServiceMethod = serviceManagerClass.getMethod("getService", String::class.java)
            val dropboxBinder = getServiceMethod.invoke(null, THANOX_PROXIED_SERVICE) as? IBinder
                ?: return false

            data = Parcel.obtain()
            reply = Parcel.obtain()

            val result = dropboxBinder.transact(THANOX_IPC_TRANS_CODE, data, reply, 0)
            if (!result) {
                return false
            }
            reply.setDataPosition(0)
            reply.dataSize() > 0
        } catch (_: Exception) {
            false
        } finally {
            data?.recycle()
            reply?.recycle()
        }
    }

    private fun isAccessibilityServiceEnabled(packageName: String): Boolean {
        return try {
            val enabledServices = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
            ) ?: return false

            val services = TextUtils.SimpleStringSplitter(':').apply {
                setString(enabledServices)
            }

            services.any { service -> service.startsWith("$packageName/") }
        } catch (_: Exception) {
            false
        }
    }

    private fun detectSceneBroadcast(): Boolean {
        val token = Random.nextLong().toULong().toString(16) +
            Random.nextLong().toULong().toString(16)
        val pocPath = "/sdcard/$token"
        val detected = try {
            val intent = Intent().apply {
                component = ComponentName(
                    "com.omarea.vtools",
                    "com.omarea.scene_mode.ReceiverShortcut",
                )
                putExtra("packageName", "x; touch $pocPath; id >> $pocPath; #")
            }
            context.sendBroadcast(intent)
            waitForScenePocFile(pocPath)
        } catch (_: Exception) {
            false
        } finally {
            runCatching { File(pocPath).delete() }
        }
        return detected
    }

    private data class MutableFinding(
        val target: DangerousAppTarget,
        val methods: LinkedHashSet<DangerousDetectionMethod> = linkedSetOf(),
    )

    companion object {
        private const val THANOX_PROXIED_SERVICE = "dropbox"
        private const val THANOX_PACKAGE = "github.tornaco.android.thanos"
        private const val SCENE_PACKAGE = "com.omarea.vtools"
        private val THANOX_IPC_TRANS_CODE =
            "github.tornaco.android.thanos.core.IPC_TRANS_CODE_THANOS_SERVER".hashCode()
    }
}
