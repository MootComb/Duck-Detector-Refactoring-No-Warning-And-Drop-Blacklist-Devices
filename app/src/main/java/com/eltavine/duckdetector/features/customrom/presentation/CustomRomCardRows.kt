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

package com.eltavine.duckdetector.features.customrom.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.customrom.domain.CustomRomFinding
import com.eltavine.duckdetector.features.customrom.domain.CustomRomModificationFinding
import com.eltavine.duckdetector.features.customrom.domain.CustomRomPackageVisibility
import com.eltavine.duckdetector.features.customrom.domain.CustomRomReport
import com.eltavine.duckdetector.features.customrom.domain.CustomRomStage
import com.eltavine.duckdetector.features.customrom.ui.model.CustomRomDetailRowModel

internal fun buildBuildRows(report: CustomRomReport): List<CustomRomDetailRowModel> {
    return when (report.stage) {
        CustomRomStage.LOADING -> placeholderRows(
            labels = listOf("System properties", "Build fields"),
            status = DetectorStatus.info(InfoKind.SUPPORT),
            value = "Pending",
        )

        CustomRomStage.FAILED -> placeholderRows(
            labels = listOf("System properties", "Build fields"),
            status = DetectorStatus.info(InfoKind.ERROR),
            value = "Error",
        )

        CustomRomStage.READY -> buildList {
            if (report.propertyFindings.isEmpty()) {
                add(
                    CustomRomDetailRowModel(
                        label = "System properties",
                        value = "Clean",
                        status = DetectorStatus.allClear(),
                    ),
                )
            } else {
                addAll(report.propertyFindings.map(::findingRow))
            }

            if (report.buildFindings.isEmpty()) {
                add(
                    CustomRomDetailRowModel(
                        label = "Build fields",
                        value = "Clean",
                        status = DetectorStatus.allClear(),
                    ),
                )
            } else {
                addAll(report.buildFindings.map(::findingRow))
            }

            if (report.modificationFindings.isEmpty()) {
                add(
                    CustomRomDetailRowModel(
                        label = "Modification",
                        value = if (report.propertyAreaAvailable) "Clean" else "Unavailable",
                        status = if (report.propertyAreaAvailable) {
                            DetectorStatus.allClear()
                        } else {
                            DetectorStatus.info(InfoKind.SUPPORT)
                        },
                        detail = if (report.propertyAreaAvailable) {
                            buildCleanModificationDetail(report)
                        } else {
                            "Native property-area coverage was unavailable on this build."
                        },
                    ),
                )
            } else {
                addAll(report.modificationFindings.map(::modificationFindingRow))
            }
        }
    }
}

internal fun buildRuntimeRows(report: CustomRomReport): List<CustomRomDetailRowModel> {
    return when (report.stage) {
        CustomRomStage.LOADING -> placeholderRows(
            labels = listOf("Packages", "Services", "Reflection"),
            status = DetectorStatus.info(InfoKind.SUPPORT),
            value = "Pending",
        )

        CustomRomStage.FAILED -> placeholderRows(
            labels = listOf("Packages", "Services", "Reflection"),
            status = DetectorStatus.info(InfoKind.ERROR),
            value = "Error",
        )

        CustomRomStage.READY -> buildList {
            if (report.packageFindings.isEmpty()) {
                add(
                    CustomRomDetailRowModel(
                        label = "Packages",
                        value = when (report.packageVisibility) {
                            CustomRomPackageVisibility.FULL -> "Clean"
                            CustomRomPackageVisibility.RESTRICTED -> "Scoped"
                            CustomRomPackageVisibility.UNKNOWN -> "Unavailable"
                        },
                        status = if (report.packageVisibility != CustomRomPackageVisibility.FULL) {
                            DetectorStatus.info(InfoKind.SUPPORT)
                        } else {
                            DetectorStatus.allClear()
                        },
                        detail = when (report.packageVisibility) {
                            CustomRomPackageVisibility.RESTRICTED ->
                                "Package visibility was restricted, so clean package results may under-report ROM apps."
                            CustomRomPackageVisibility.UNKNOWN ->
                                "Package inventory was unavailable or anomalous, so package absence is inconclusive."
                            CustomRomPackageVisibility.FULL -> null
                        },
                    ),
                )
            } else {
                addAll(report.packageFindings.map(::findingRow))
            }

            if (report.serviceFindings.isEmpty()) {
                add(
                    CustomRomDetailRowModel(
                        label = "Services",
                        value = "Clean",
                        status = DetectorStatus.allClear(),
                        detail = "Listed ${report.listedServiceCount} services.",
                    ),
                )
            } else {
                addAll(report.serviceFindings.map(::findingRow))
            }

            if (report.reflectionFindings.isEmpty()) {
                add(
                    CustomRomDetailRowModel(
                        label = "Reflection",
                        value = "Clean",
                        status = DetectorStatus.allClear(),
                    ),
                )
            } else {
                addAll(report.reflectionFindings.map(::findingRow))
            }
        }
    }
}

internal fun buildFrameworkRows(report: CustomRomReport): List<CustomRomDetailRowModel> {
    return when (report.stage) {
        CustomRomStage.LOADING -> placeholderRows(
            labels = listOf(
                "Resource maps",
                "Platform files",
                "Recovery scripts",
                "SELinux policy",
                "Native symbols",
                "Product overlays"
            ),
            status = DetectorStatus.info(InfoKind.SUPPORT),
            value = "Pending",
        )

        CustomRomStage.FAILED -> placeholderRows(
            labels = listOf(
                "Resource maps",
                "Platform files",
                "Recovery scripts",
                "SELinux policy",
                "Native symbols",
                "Product overlays"
            ),
            status = DetectorStatus.info(InfoKind.ERROR),
            value = "Error",
        )

        CustomRomStage.READY -> buildList {
            if (!report.nativeAvailable) {
                addUnavailableFrameworkRow("Resource maps")
                addUnavailableFrameworkRow("Platform files")
                addUnavailableFrameworkRow("Recovery scripts")
                addUnavailableFrameworkRow("SELinux policy")
                addUnavailableFrameworkRow("Native symbols")
                addUnavailableFrameworkRow("Product overlays")
                return@buildList
            }

            if (report.resourceInjectionFindings.isEmpty()) {
                add(
                    CustomRomDetailRowModel(
                        "Resource maps",
                        "Clean",
                        DetectorStatus.allClear()
                    )
                )
            } else {
                addAll(report.resourceInjectionFindings.map(::findingRow))
            }

            if (report.platformFileFindings.isEmpty()) {
                add(
                    CustomRomDetailRowModel(
                        "Platform files",
                        "Clean",
                        DetectorStatus.allClear()
                    )
                )
            } else {
                addAll(report.platformFileFindings.map(::findingRow))
            }

            if (report.recoveryScripts.isEmpty()) {
                add(
                    CustomRomDetailRowModel(
                        "Recovery scripts",
                        "Clean",
                        DetectorStatus.allClear()
                    )
                )
            } else {
                addAll(
                    report.recoveryScripts.map { script ->
                        CustomRomDetailRowModel(
                            label = script.substringAfterLast('/'),
                            value = "Custom ROM",
                            status = DetectorStatus.warning(),
                            detail = script,
                            detailMonospace = true,
                        )
                    },
                )
            }

            if (report.policyFindings.isEmpty()) {
                add(
                    CustomRomDetailRowModel(
                        "SELinux policy",
                        "Clean",
                        DetectorStatus.allClear()
                    )
                )
            } else {
                addAll(report.policyFindings.map(::findingRow))
            }

            if (report.symbolFindings.isEmpty()) {
                add(
                    if (report.symbolScanAvailable) {
                        CustomRomDetailRowModel(
                            "Native symbols",
                            "Clean",
                            DetectorStatus.allClear()
                        )
                    } else {
                        CustomRomDetailRowModel(
                            "Native symbols",
                            "Unsupported",
                            DetectorStatus.info(InfoKind.SUPPORT),
                            detail = "Native symbol trace detection only runs on Android 10+.",
                        )
                    }
                )
            } else {
                addAll(report.symbolFindings.map(::findingRow))
            }

            if (report.overlayFindings.isEmpty()) {
                add(
                    CustomRomDetailRowModel(
                        "Product overlays",
                        "Clean",
                        DetectorStatus.allClear()
                    )
                )
            } else {
                addAll(report.overlayFindings.map(::findingRow))
            }
        }
    }
}

internal fun findingRow(
    finding: CustomRomFinding,
): CustomRomDetailRowModel {
    return CustomRomDetailRowModel(
        label = finding.signal,
        value = finding.romName,
        status = DetectorStatus.warning(),
        detail = finding.detail,
        detailMonospace = true,
    )
}

internal fun modificationFindingRow(
    finding: CustomRomModificationFinding,
): CustomRomDetailRowModel {
    return CustomRomDetailRowModel(
        label = finding.signal,
        value = finding.summary,
        status = DetectorStatus.warning(),
        detail = "${finding.category}: ${finding.detail}",
        detailMonospace = true,
    )
}

internal fun placeholderRows(
    labels: List<String>,
    status: DetectorStatus,
    value: String,
): List<CustomRomDetailRowModel> {
    return labels.map { label ->
        CustomRomDetailRowModel(
            label = label,
            value = value,
            status = status,
        )
    }
}

internal fun MutableList<CustomRomDetailRowModel>.addUnavailableFrameworkRow(label: String) {
    add(
        CustomRomDetailRowModel(
            label = label,
            value = "Unavailable",
            status = DetectorStatus.info(InfoKind.SUPPORT),
            detail = "Native framework trace coverage was unavailable on this build.",
        )
    )
}
