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

package com.eltavine.duckdetector.features.virtualization.data.service

import android.content.Context
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationNativeBridge
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationRemoteProfile
import com.eltavine.duckdetector.features.virtualization.data.probes.DexPathProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.DexPathProbeResult
import com.eltavine.duckdetector.features.virtualization.data.probes.ProcMountViewScanner
import com.eltavine.duckdetector.features.virtualization.data.probes.UidIdentityProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.UidIdentityProbeResult

internal object VirtualizationProbePayloadBuilder {

    fun buildSnapshotPayload(
        context: Context,
        profile: VirtualizationRemoteProfile,
        classLoader: ClassLoader?,
        nativeBridge: VirtualizationNativeBridge,
    ): String = buildSnapshotPayload(
        environment = AndroidSnapshotEnvironment(context, classLoader),
        profile = profile,
        nativeBridge = nativeBridge,
    )

    fun buildSnapshotPayload(
        environment: SnapshotEnvironment,
        profile: VirtualizationRemoteProfile,
        nativeBridge: VirtualizationNativeBridge,
    ): String {
        return runCatching {
            val dexPathResult = environment.probeDexPath()
            val uidIdentityResult = environment.probeUidIdentity()
            // Helpers do not consume EGL fields or renderer findings. Issue #141 reports a crash
            // during EGL initialization in an isolated helper; the exact pointer corruption
            // mechanism is unconfirmed. Android 16 policy denies ordinary isolated apps GPU access.
            // helper 不消费 EGL 结果；#141 记录了 isolated helper 的 EGL 初始化崩溃，具体指针损坏原因未确认。
            // https://android.googlesource.com/platform/system/sepolicy/+/refs/tags/android-16.0.0_r1/private/isolated_app_all.te
            val snapshot = nativeBridge.collectSnapshot(probeRenderer = false)

            buildString {
                appendLine("AVAILABLE=1")
                appendLine("PROFILE=${profile.name}")
                appendLine("NATIVE_AVAILABLE=${if (snapshot.available) 1 else 0}")
                appendLine("UID=${uidIdentityResult.uid}")
                appendLine("PACKAGE_NAME=${environment.packageName.encodeValue()}")
                appendLine("PROCESS_NAME=${uidIdentityResult.processName.encodeValue()}")
                appendLine("UID_NAME=${uidIdentityResult.uidName.encodeValue()}")
                appendLine(
                    "PACKAGES_FOR_UID=${uidIdentityResult.packagesForUid.encodeList()}",
                )
                appendLine(
                    "CLASS_PATH_ENTRIES=${dexPathResult.classPathEntries.encodeList()}",
                )
                appendLine("SOURCE_DIR=${dexPathResult.sourceDir.encodeValue()}")
                appendLine(
                    "SPLIT_SOURCE_DIRS=${dexPathResult.splitSourceDirs.encodeList()}",
                )
                appendLine(
                    "MOUNT_NAMESPACE_INODE=${snapshot.mountNamespaceInode.encodeValue()}",
                )
                appendLine("APEX_MOUNT_KEY=${snapshot.apexMountKey.encodeValue()}")
                appendLine("SYSTEM_MOUNT_KEY=${snapshot.systemMountKey.encodeValue()}")
                appendLine("VENDOR_MOUNT_KEY=${snapshot.vendorMountKey.encodeValue()}")
                // Isolated services lack normal app-private storage; filesDir/cacheDir can throw
                // ENOENT and erase the payload. Keep storage-only probes out of this branch.
                // isolated service 没有普通 app-private storage，不能让预期 ENOENT 抹掉 mount 证据。
                // https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/res/res/values/attrs_manifest.xml
                if (profile != VirtualizationRemoteProfile.ISOLATED) {
                    appendLine("FILES_DIR=${environment.filesDir.encodeValue()}")
                    appendLine("CACHE_DIR=${environment.cacheDir.encodeValue()}")
                }
                appendLine("CODE_PATH=${environment.codePath.encodeValue()}")
                snapshot.findings.forEach { finding ->
                    append("FINDING=")
                    append(finding.group.encodeValue())
                    append('\t')
                    append(finding.severity.encodeValue())
                    append('\t')
                    append(finding.label.encodeValue())
                    append('\t')
                    append(finding.value.encodeValue())
                    append('\t')
                    appendLine(finding.detail.encodeValue())
                }
            }
        }.getOrElse { throwable ->
            buildString {
                appendLine("AVAILABLE=0")
                appendLine("PROFILE=${profile.name}")
                appendLine("NATIVE_AVAILABLE=0")
                appendLine("ERROR=${(throwable.message ?: "Remote snapshot failed.").encodeValue()}")
            }
        }
    }

    fun buildProcMountViewPayload(profile: VirtualizationRemoteProfile): String {
        if (profile != VirtualizationRemoteProfile.ISOLATED) {
            return "AVAILABLE=0\nPROFILE=${profile.name}\nERROR=Isolated profile required.\n"
        }
        val mountView = ProcMountViewScanner().scan()
        return buildString {
            appendLine("AVAILABLE=1")
            appendLine("PROFILE=${profile.name}")
            appendLine("NATIVE_AVAILABLE=0")
            appendLine("PROC_MOUNT_VIEW_AVAILABLE=${if (mountView.available) 1 else 0}")
            appendLine("PROC_MOUNT_VIEW_COUNT=${mountView.distinctViewCount}")
            appendLine("PROC_MOUNT_VIEW_EXPECTED=${mountView.expectedViewCount}")
            appendLine("PROC_MOUNT_VIEW_PIDS=${mountView.scannedPidCount}")
            appendLine("PROC_MOUNT_VIEW_DIVERGENT=${if (mountView.divergent) 1 else 0}")
            appendLine("PROC_MOUNT_VIEW_TOKEN_HIT=${if (mountView.tokenHit) 1 else 0}")
            appendLine("PROC_MOUNT_VIEW_TOKEN_KIND=${mountView.tokenKind.encodeValue()}")
            appendLine("PROC_MOUNT_VIEW_TOKEN_DETAIL=${mountView.tokenHitDetail.encodeValue()}")
            appendLine("PROC_MOUNT_VIEW_DETAIL=${mountView.detail.encodeValue()}")
        }
    }

    // Keep platform reads lazy: isolated helpers must never touch app-private storage, and read
    // failures must remain inside buildSnapshotPayload's error boundary.
    internal interface SnapshotEnvironment {
        fun probeDexPath(): DexPathProbeResult
        fun probeUidIdentity(): UidIdentityProbeResult
        val packageName: String
        val filesDir: String
        val cacheDir: String
        val codePath: String
    }

    private class AndroidSnapshotEnvironment(
        private val context: Context,
        private val classLoader: ClassLoader?,
    ) : SnapshotEnvironment {
        private val appContext: Context by lazy { context.applicationContext }

        override fun probeDexPath(): DexPathProbeResult = DexPathProbe(
            context = appContext,
            classLoaderProvider = { classLoader },
        ).probe()

        override fun probeUidIdentity(): UidIdentityProbeResult = UidIdentityProbe(appContext).probe()

        override val packageName: String get() = appContext.packageName
        override val filesDir: String get() = appContext.filesDir.absolutePath
        override val cacheDir: String get() = appContext.cacheDir.absolutePath
        override val codePath: String get() = appContext.applicationInfo.sourceDir
    }

    private fun String.encodeValue(): String {
        return replace("\n", "\\n")
            .replace("\r", "\\r")
    }

    private fun List<String>.encodeList(): String {
        return distinct()
            .filter { it.isNotBlank() }
            .joinToString(separator = VirtualizationProbeProtocol.LIST_SEPARATOR) {
                it.encodeValue()
            }
    }
}
