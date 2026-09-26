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

package com.eltavine.duckdetector.features.customrom.data.repository

import android.content.Context
import android.os.Build
import com.eltavine.duckdetector.capability.packageinventory.data.AndroidInstalledPackageInventoryReader
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageInventoryReader
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageInventoryResult
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.platform.HiddenServiceManager
import com.eltavine.duckdetector.features.customrom.data.native.CustomRomNativeBridge
import com.eltavine.duckdetector.features.customrom.data.rules.CustomRomCatalog
import com.eltavine.duckdetector.features.customrom.domain.CustomRomFinding
import com.eltavine.duckdetector.features.customrom.domain.CustomRomModificationFinding
import com.eltavine.duckdetector.features.customrom.domain.CustomRomPackageVisibility
import com.eltavine.duckdetector.features.customrom.domain.CustomRomReport
import com.eltavine.duckdetector.features.customrom.domain.CustomRomStage
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class CustomRomRepository(
    private val context: Context,
    private val packageInventoryReader: InstalledPackageInventoryReader =
        AndroidInstalledPackageInventoryReader(context.applicationContext),
    private val nativeBridge: CustomRomNativeBridge = CustomRomNativeBridge(),
    private val fileExists: (String) -> Boolean = { path -> File(path).exists() },
    private val propertyReader: CustomRomPropertyReader = DefaultCustomRomPropertyReader(),
) : DetectorScanner<CustomRomReport> {
    private val modificationProbe = CustomRomModificationProbe()

    override suspend fun scan(): CustomRomReport = withContext(Dispatchers.IO) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                CustomRomReport.failed(throwable.message ?: "Custom ROM scan failed.")
            }
    }

    private fun scanInternal(): CustomRomReport {
        val isPixel = isPixelDevice()
        val propertyFindings = detectPropertyFindings(isPixel)
        val buildFindings = detectBuildFindings(isPixel)
        val packageInventory = packageInventoryReader.read()
        val installedPackages = (packageInventory as? InstalledPackageInventoryResult.Available)
            ?.inventory
            ?.packageNames
            .orEmpty()
        val packageVisibility = packageInventory.toCustomRomVisibility()
        val packageFindings = detectPackageFindings(installedPackages, isPixel)
        val serviceScan = detectServiceFindings(isPixel)
        val serviceFindings = serviceScan.findings
        val listedServiceCount = serviceScan.listedCount
        val reflectionFindings = detectReflectionFindings(isPixel)
        val nativeSnapshot = nativeBridge.collectSnapshot()
        val checkedModificationPropertyCount = modificationProbe.checkedPropertyCount
        val modificationFindings = buildList {
            addAll(modificationProbe.inspect(nativeSnapshot))
            addAll(detectBootloaderFinding())
        }
        val platformFileFindings =
            CustomRomPlatformFileResolver.resolve(
                nativeSnapshot = nativeSnapshot,
                isPixel = isPixel,
                shouldSkip = ::shouldSkip,
                fileExists = fileExists,
            )
        val resourceInjectionFindings = nativeSnapshot.resourceInjectionFindings
        val symbolScanAvailable = nativeSnapshot.symbolScanAvailable
        val symbolFindings = if (symbolScanAvailable) {
            nativeSnapshot.symbolFindings.filterNot { shouldSkip(it.romName, isPixel) }
        } else {
            emptyList()
        }
        val policyFindings =
            nativeSnapshot.policyFindings.filterNot { shouldSkip(it.romName, isPixel) }
        val overlayFindings =
            nativeSnapshot.overlayFindings.filterNot { shouldSkip(it.romName, isPixel) }

        val detectedRoms = linkedSetOf<String>().apply {
            addAll(propertyFindings.map { it.romName })
            addAll(buildFindings.map { it.romName })
            addAll(packageFindings.map { it.romName })
            addAll(serviceFindings.map { it.romName })
            addAll(reflectionFindings.map { it.romName })
            addAll(platformFileFindings.map { it.romName })
            addAll(resourceInjectionFindings.map { it.romName })
            addAll(policyFindings.map { it.romName })
            addAll(overlayFindings.map { it.romName })
            if (nativeSnapshot.recoveryScripts.isNotEmpty()) {
                add("Custom ROM")
            }
        }.toList()

        val methods = buildMethods(
            propertyFindings = propertyFindings,
            buildFindings = buildFindings,
            modificationFindings = modificationFindings,
            propertyAreaAvailable = nativeSnapshot.propertyAreaAvailable,
            packageFindings = packageFindings,
            packageVisibility = packageVisibility,
            serviceFindings = serviceFindings,
            listedServiceCount = listedServiceCount,
            serviceScanAvailable = serviceScan.available,
            reflectionFindings = reflectionFindings,
            platformFileFindings = platformFileFindings,
            resourceInjectionFindings = resourceInjectionFindings,
            recoveryScripts = nativeSnapshot.recoveryScripts,
            policyFindings = policyFindings,
            overlayFindings = overlayFindings,
            symbolFindings = symbolFindings,
            nativeAvailable = nativeSnapshot.available,
            symbolScanAvailable = symbolScanAvailable,
            checkedModificationPropertyCount = checkedModificationPropertyCount,
            propertyAreaContextCount = nativeSnapshot.propertyAreaContextCount,
        )

        return CustomRomReport(
            stage = CustomRomStage.READY,
            packageVisibility = packageVisibility,
            detectedRoms = detectedRoms,
            propertyFindings = propertyFindings,
            buildFindings = buildFindings,
            modificationFindings = modificationFindings,
            packageFindings = packageFindings,
            serviceFindings = serviceFindings,
            reflectionFindings = reflectionFindings,
            platformFileFindings = platformFileFindings,
            resourceInjectionFindings = resourceInjectionFindings,
            recoveryScripts = nativeSnapshot.recoveryScripts,
            policyFindings = policyFindings,
            overlayFindings = overlayFindings,
            symbolFindings = symbolFindings,
            nativeAvailable = nativeSnapshot.available,
            propertyAreaAvailable = nativeSnapshot.propertyAreaAvailable,
            symbolScanAvailable = symbolScanAvailable,
            checkedPropertyCount = CustomRomCatalog.propertySignatures.size,
            checkedBuildFieldCount = CustomRomCatalog.buildFields.size,
            checkedModificationPropertyCount = checkedModificationPropertyCount,
            checkedPackageCount = CustomRomCatalog.packageSignatures.size,
            checkedServiceCount = CustomRomCatalog.specificServices.size,
            listedServiceCount = listedServiceCount,
            serviceScanAvailable = serviceScan.available,
            methods = methods,
            propertyAreaContextCount = nativeSnapshot.propertyAreaContextCount,
            propertyAreaAnomalyCount = nativeSnapshot.propertyAreaAnomalyCount,
            propertyAreaItemAnomalyCount = nativeSnapshot.propertyAreaItemAnomalyCount,
        )
    }

    private fun detectPropertyFindings(
        isPixel: Boolean,
    ): List<CustomRomFinding> {
        return CustomRomCatalog.propertySignatures.mapNotNull { signature ->
            val value = propertyReader.read(signature.property)?.trim()?.takeIf { it.isNotBlank() }
                ?: return@mapNotNull null
            if (shouldSkip(signature.romName, isPixel)) {
                return@mapNotNull null
            }
            CustomRomFinding(
                romName = signature.romName,
                signal = signature.property,
                detail = value,
            )
        }.distinct()
    }

    private fun detectBuildFindings(
        isPixel: Boolean,
    ): List<CustomRomFinding> {
        val fieldValues = listOf(
            "Build.DISPLAY" to Build.DISPLAY,
            "Build.FINGERPRINT" to Build.FINGERPRINT,
            "Build.HOST" to Build.HOST,
        )

        return buildList {
            fieldValues.forEach { (fieldName, rawValue) ->
                val value = rawValue?.takeIf { it.isNotBlank() } ?: return@forEach
                val lower = value.lowercase()
                CustomRomCatalog.buildFieldKeywords.forEach { signature ->
                    if (lower.contains(signature.keyword) && !shouldSkip(
                            signature.romName,
                            isPixel
                        )
                    ) {
                        add(
                            CustomRomFinding(
                                romName = signature.romName,
                                signal = fieldName,
                                detail = value,
                            ),
                        )
                    }
                }
            }
        }.distinct()
    }

    private fun detectPackageFindings(
        installedPackages: Set<String>,
        isPixel: Boolean,
    ): List<CustomRomFinding> {
        return CustomRomCatalog.packageSignatures.mapNotNull { signature ->
            if (signature.packageName !in installedPackages || shouldSkip(
                    signature.romName,
                    isPixel
                )
            ) {
                return@mapNotNull null
            }
            CustomRomFinding(
                romName = signature.romName,
                signal = signature.appName,
                detail = signature.packageName,
            )
        }.distinct()
    }

    private fun detectServiceFindings(isPixel: Boolean): ServiceScan {
        val findings = linkedSetOf<CustomRomFinding>()

        val lookedUpServices = runCatching {
            CustomRomCatalog.specificServices.forEach { signature ->
                val binder = HiddenServiceManager.getService(signature.serviceName).getOrThrow()
                if (binder != null && !shouldSkip(signature.romName, isPixel)) {
                    findings += CustomRomFinding(
                        romName = signature.romName,
                        signal = signature.serviceName,
                        detail = "ServiceManager.getService",
                    )
                }
            }
        }.isSuccess

        val serviceNames = HiddenServiceManager.listServices().getOrNull()
        serviceNames?.forEach { serviceName ->
            val lower = serviceName.lowercase()
            CustomRomCatalog.servicePatterns.forEach { (pattern, romName) ->
                if (lower.contains(pattern) && !shouldSkip(romName, isPixel)) {
                    findings += CustomRomFinding(
                        romName = romName,
                        signal = serviceName,
                        detail = "ServiceManager.listServices",
                    )
                }
            }
        }

        return ServiceScan(
            findings = findings.toList(),
            listedCount = serviceNames?.size ?: 0,
            available = lookedUpServices && serviceNames != null,
        )
    }

    private data class ServiceScan(
        val findings: List<CustomRomFinding>,
        val listedCount: Int,
        val available: Boolean,
    )

    private fun detectReflectionFindings(
        isPixel: Boolean,
    ): List<CustomRomFinding> {
        return buildList {
            CustomRomCatalog.reflectionTargets.forEach { target ->
                if (shouldSkip(target.romName, isPixel)) {
                    return@forEach
                }
                runCatching {
                    val clazz = Class.forName(target.className)
                    val field = clazz.getDeclaredField(target.fieldName)
                    field.isAccessible = true
                    val value = field.get(null)?.toString()?.takeIf { it.isNotBlank() }
                        ?: return@runCatching
                    add(
                        CustomRomFinding(
                            romName = target.romName,
                            signal = "${target.className}.${target.fieldName}",
                            detail = value,
                        ),
                    )
                }
            }
        }.distinct()
    }

    private fun detectBootloaderFinding(): List<CustomRomModificationFinding> =
        listOfNotNull(bootloaderUnlockFinding(propertyReader.read("ro.boot.flash.locked")))

    private fun shouldSkip(
        romName: String,
        isPixel: Boolean,
    ): Boolean {
        return isPixel && romName == "PixelExperience"
    }

    private fun isPixelDevice(): Boolean {
        return Build.BRAND.equals("google", ignoreCase = true) &&
                Build.MODEL.startsWith("Pixel", ignoreCase = true)
    }

    private fun InstalledPackageInventoryResult.toCustomRomVisibility(): CustomRomPackageVisibility {
        val visibility = (this as? InstalledPackageInventoryResult.Available)
            ?.inventory
            ?.visibility
            ?: InstalledPackageVisibility.UNKNOWN
        return when (visibility) {
            InstalledPackageVisibility.UNKNOWN -> CustomRomPackageVisibility.UNKNOWN
            InstalledPackageVisibility.FULL -> CustomRomPackageVisibility.FULL
            InstalledPackageVisibility.RESTRICTED -> CustomRomPackageVisibility.RESTRICTED
        }
    }
}
