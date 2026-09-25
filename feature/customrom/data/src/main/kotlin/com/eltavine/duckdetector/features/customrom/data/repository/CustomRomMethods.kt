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

import com.eltavine.duckdetector.features.customrom.domain.CustomRomFinding
import com.eltavine.duckdetector.features.customrom.domain.CustomRomModificationFinding
import com.eltavine.duckdetector.features.customrom.domain.CustomRomMethodOutcome
import com.eltavine.duckdetector.features.customrom.domain.CustomRomMethodResult
import com.eltavine.duckdetector.features.customrom.domain.CustomRomPackageVisibility

internal fun buildMethods(
    propertyFindings: List<CustomRomFinding>,
    buildFindings: List<CustomRomFinding>,
    modificationFindings: List<CustomRomModificationFinding>,
    propertyAreaAvailable: Boolean,
    packageFindings: List<CustomRomFinding>,
    packageVisibility: CustomRomPackageVisibility,
    serviceFindings: List<CustomRomFinding>,
    listedServiceCount: Int,
    reflectionFindings: List<CustomRomFinding>,
    platformFileFindings: List<CustomRomFinding>,
    resourceInjectionFindings: List<CustomRomFinding>,
    recoveryScripts: List<String>,
    policyFindings: List<CustomRomFinding>,
    overlayFindings: List<CustomRomFinding>,
    symbolFindings: List<CustomRomFinding>,
    nativeAvailable: Boolean,
    symbolScanAvailable: Boolean,
    checkedModificationPropertyCount: Int,
    propertyAreaContextCount: Int,
): List<CustomRomMethodResult> {
    val nativeFileCount =
        platformFileFindings.size + recoveryScripts.size + overlayFindings.size
    return listOf(
        CustomRomMethodResult(
            label = "propertyScan",
            summary = if (propertyFindings.isNotEmpty()) "${propertyFindings.size} hit(s)" else "Clean",
            outcome = if (propertyFindings.isNotEmpty()) CustomRomMethodOutcome.DETECTED else CustomRomMethodOutcome.CLEAN,
            detail = propertyFindings.takeIf { it.isNotEmpty() }
                ?.joinToString(separator = "\n") {
                    "${it.signal} = ${it.detail}"
                },
        ),
        CustomRomMethodResult(
            label = "buildFieldScan",
            summary = if (buildFindings.isNotEmpty()) "${buildFindings.size} hit(s)" else "Clean",
            outcome = if (buildFindings.isNotEmpty()) CustomRomMethodOutcome.DETECTED else CustomRomMethodOutcome.CLEAN,
            detail = buildFindings.takeIf { it.isNotEmpty() }?.joinToString(separator = "\n") {
                "${it.signal} = ${it.detail}"
            },
        ),
        CustomRomMethodResult(
            label = "modificationScan",
            summary = when {
                modificationFindings.isNotEmpty() -> "${modificationFindings.size} signal(s)"
                propertyAreaAvailable -> "Clean"
                else -> "Unavailable"
            },
            outcome = when {
                modificationFindings.isNotEmpty() -> CustomRomMethodOutcome.DETECTED
                propertyAreaAvailable -> CustomRomMethodOutcome.CLEAN
                else -> CustomRomMethodOutcome.SUPPORT
            },
            detail = when {
                modificationFindings.isNotEmpty() ->
                    modificationFindings.joinToString(separator = "\n") {
                        "${it.category}: ${it.signal} = ${it.summary} (${it.detail})"
                    }

                propertyAreaAvailable -> buildCleanModificationDetail(
                    checkedModificationPropertyCount = checkedModificationPropertyCount,
                    propertyAreaContextCount = propertyAreaContextCount,
                )

                else ->
                    "Native property-area coverage was unavailable on this build."
            },
        ),
        CustomRomMethodResult(
            label = "packageScan",
            summary = when {
                packageFindings.isNotEmpty() -> "${packageFindings.size} package(s)"
                packageVisibility == CustomRomPackageVisibility.RESTRICTED -> "Scoped"
                packageVisibility == CustomRomPackageVisibility.UNKNOWN -> "Unavailable"
                else -> "Clean"
            },
            outcome = when {
                packageFindings.isNotEmpty() -> CustomRomMethodOutcome.DETECTED
                packageVisibility != CustomRomPackageVisibility.FULL -> CustomRomMethodOutcome.SUPPORT
                else -> CustomRomMethodOutcome.CLEAN
            },
            detail = when {
                packageFindings.isNotEmpty() -> packageFindings.joinToString(separator = "\n") {
                    "${it.signal}: ${it.detail}"
                }

                packageVisibility == CustomRomPackageVisibility.RESTRICTED ->
                    "PackageManager visibility looked restricted on this device profile."

                packageVisibility == CustomRomPackageVisibility.UNKNOWN ->
                    "PackageManager inventory was unavailable or failed its caller-package baseline."

                else -> null
            },
        ),
        CustomRomMethodResult(
            label = "serviceScan",
            summary = if (serviceFindings.isNotEmpty()) "${serviceFindings.size} service(s)" else "Clean",
            outcome = if (serviceFindings.isNotEmpty()) CustomRomMethodOutcome.DETECTED else CustomRomMethodOutcome.CLEAN,
            detail = buildString {
                append("Listed services: $listedServiceCount")
                if (serviceFindings.isNotEmpty()) {
                    appendLine()
                    append(
                        serviceFindings.joinToString(separator = "\n") {
                            "${it.signal}: ${it.detail}"
                        },
                    )
                }
            },
        ),
        CustomRomMethodResult(
            label = "reflectionScan",
            summary = if (reflectionFindings.isNotEmpty()) "Constants found" else "Clean",
            outcome = if (reflectionFindings.isNotEmpty()) CustomRomMethodOutcome.DETECTED else CustomRomMethodOutcome.CLEAN,
            detail = reflectionFindings.takeIf { it.isNotEmpty() }
                ?.joinToString(separator = "\n") {
                    "${it.signal} = ${it.detail}"
                },
        ),
        CustomRomMethodResult(
            label = "mapsInjection",
            summary = when {
                resourceInjectionFindings.isNotEmpty() -> "${resourceInjectionFindings.size} trace(s)"
                nativeAvailable -> "Clean"
                else -> "Unavailable"
            },
            outcome = when {
                resourceInjectionFindings.isNotEmpty() -> CustomRomMethodOutcome.DETECTED
                nativeAvailable -> CustomRomMethodOutcome.CLEAN
                else -> CustomRomMethodOutcome.SUPPORT
            },
            detail = resourceInjectionFindings.takeIf { it.isNotEmpty() }
                ?.joinToString(separator = "\n\n") {
                    "${it.signal}: ${it.detail}"
                },
        ),
        CustomRomMethodResult(
            label = "nativeFiles",
            summary = when {
                nativeFileCount > 0 -> "$nativeFileCount trace(s)"
                nativeAvailable -> "Clean"
                else -> "Unavailable"
            },
            outcome = when {
                nativeFileCount > 0 -> CustomRomMethodOutcome.DETECTED
                nativeAvailable -> CustomRomMethodOutcome.CLEAN
                else -> CustomRomMethodOutcome.SUPPORT
            },
            detail = buildNativeFilesDetail(
                platformFileFindings,
                recoveryScripts,
                overlayFindings
            ),
        ),
        CustomRomMethodResult(
            label = "nativePolicy",
            summary = when {
                policyFindings.isNotEmpty() -> "${policyFindings.size} hit(s)"
                nativeAvailable -> "Clean"
                else -> "Unavailable"
            },
            outcome = when {
                policyFindings.isNotEmpty() -> CustomRomMethodOutcome.DETECTED
                nativeAvailable -> CustomRomMethodOutcome.CLEAN
                else -> CustomRomMethodOutcome.SUPPORT
            },
            detail = policyFindings.takeIf { it.isNotEmpty() }?.joinToString(separator = "\n") {
                "${it.romName}: ${it.detail}"
            },
        ),
        CustomRomMethodResult(
            label = "nativeSymbols",
            summary = when {
                symbolFindings.isNotEmpty() -> "${symbolFindings.size} trace(s)"
                !nativeAvailable -> "Unavailable"
                !symbolScanAvailable -> "Unsupported"
                else -> "Clean"
            },
            outcome = when {
                symbolFindings.isNotEmpty() -> CustomRomMethodOutcome.DETECTED
                !nativeAvailable -> CustomRomMethodOutcome.SUPPORT
                !symbolScanAvailable -> CustomRomMethodOutcome.SUPPORT
                else -> CustomRomMethodOutcome.CLEAN
            },
            detail = when {
                symbolFindings.isNotEmpty() ->
                    symbolFindings.joinToString(separator = "\n") {
                        "${it.signal}: ${it.detail}"
                    }

                !nativeAvailable ->
                    "Native framework coverage was unavailable on this build."

                !symbolScanAvailable ->
                    "Native symbol trace detection only runs on Android 10+."

                else -> null
            },
        ),
        CustomRomMethodResult(
            label = "nativeLibrary",
            summary = if (nativeAvailable) "Loaded" else "Unavailable",
            outcome = if (nativeAvailable) CustomRomMethodOutcome.CLEAN else CustomRomMethodOutcome.SUPPORT,
        ),
    )
}

internal fun buildCleanModificationDetail(
    checkedModificationPropertyCount: Int,
    propertyAreaContextCount: Int,
): String {
    return buildString {
        append("Tracked property area, serial, and residual value checks were clean")
        if (checkedModificationPropertyCount > 0 || propertyAreaContextCount > 0) {
            append("; checked ")
            if (checkedModificationPropertyCount > 0) {
                append(checkedModificationPropertyCount)
                append(" tracked property name(s)")
            } else {
                append("tracked property names")
            }
        }
        if (propertyAreaContextCount > 0) {
            append(" across ")
            append(propertyAreaContextCount)
            append(" property-area context(s)")
        }
        append('.')
    }
}

internal fun buildNativeFilesDetail(
    platformFileFindings: List<CustomRomFinding>,
    recoveryScripts: List<String>,
    overlayFindings: List<CustomRomFinding>,
): String? {
    return buildString {
        platformFileFindings.forEach { finding ->
            appendLine("${finding.romName}: ${finding.detail}")
        }
        recoveryScripts.forEach { script ->
            appendLine("Script: $script")
        }
        overlayFindings.forEach { finding ->
            appendLine("${finding.romName}: ${finding.detail}")
        }
    }.trim().ifBlank { null }
}
