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
import com.eltavine.duckdetector.features.customrom.domain.CustomRomMethodOutcome
import com.eltavine.duckdetector.features.customrom.domain.CustomRomMethodResult
import com.eltavine.duckdetector.features.customrom.domain.CustomRomPackageVisibility
import com.eltavine.duckdetector.features.customrom.domain.CustomRomReport
import com.eltavine.duckdetector.features.customrom.domain.CustomRomStage
import com.eltavine.duckdetector.features.customrom.presentation.model.CustomRomDetailRowModel

internal fun buildMethodRows(report: CustomRomReport): List<CustomRomDetailRowModel> {
    return when (report.stage) {
        CustomRomStage.LOADING -> placeholderRows(
            labels = listOf(
                "propertyScan",
                "buildFieldScan",
                "modificationScan",
                "packageScan",
                "serviceScan",
                "reflectionScan",
                "mapsInjection",
                "nativeFiles",
                "nativePolicy",
                "nativeSymbols",
                "nativeLibrary",
            ),
            status = DetectorStatus.info(InfoKind.SUPPORT),
            value = "Pending",
        )

        CustomRomStage.FAILED -> placeholderRows(
            labels = listOf(
                "propertyScan",
                "buildFieldScan",
                "modificationScan",
                "packageScan",
                "serviceScan",
                "reflectionScan",
                "mapsInjection",
                "nativeFiles",
                "nativePolicy",
                "nativeSymbols",
                "nativeLibrary",
            ),
            status = DetectorStatus.info(InfoKind.ERROR),
            value = "Failed",
        )

        CustomRomStage.READY -> report.methods.map { result ->
            CustomRomDetailRowModel(
                label = result.label,
                value = result.summary,
                status = methodStatus(result),
                detail = result.detail,
                detailMonospace = true,
            )
        }
    }
}

internal fun buildScanRows(report: CustomRomReport): List<CustomRomDetailRowModel> {
    return when (report.stage) {
        CustomRomStage.LOADING -> placeholderRows(
            labels = listOf(
                "Properties checked",
                "Build fields checked",
                "Modification props checked",
                "Prop area contexts",
                "Prop area anomalies",
                "Prop item anomalies",
                "Packages checked",
                "Package visibility",
                "Named services checked",
                "Services listed",
                "Native library",
            ),
            status = DetectorStatus.info(InfoKind.SUPPORT),
            value = "Pending",
        )

        CustomRomStage.FAILED -> placeholderRows(
            labels = listOf(
                "Properties checked",
                "Build fields checked",
                "Modification props checked",
                "Prop area contexts",
                "Prop area anomalies",
                "Prop item anomalies",
                "Packages checked",
                "Package visibility",
                "Named services checked",
                "Services listed",
                "Native library",
            ),
            status = DetectorStatus.info(InfoKind.ERROR),
            value = "Error",
        )

        CustomRomStage.READY -> listOf(
            CustomRomDetailRowModel(
                label = "Properties checked",
                value = report.checkedPropertyCount.toString(),
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
            CustomRomDetailRowModel(
                label = "Build fields checked",
                value = report.checkedBuildFieldCount.toString(),
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
            CustomRomDetailRowModel(
                label = "Modification props checked",
                value = if (report.propertyAreaAvailable) {
                    report.checkedModificationPropertyCount.toString()
                } else {
                    "Unavailable"
                },
                status = DetectorStatus.info(InfoKind.SUPPORT),
                detail = if (report.propertyAreaAvailable) {
                    null
                } else {
                    "Native property-area coverage was unavailable on this build."
                },
            ),
            CustomRomDetailRowModel(
                label = "Prop area contexts",
                value = if (report.propertyAreaAvailable) {
                    report.propertyAreaContextCount.toString()
                } else {
                    "Unavailable"
                },
                status = if (report.propertyAreaAvailable) {
                    if (report.propertyAreaContextCount > 0) {
                        DetectorStatus.allClear()
                    } else {
                        DetectorStatus.info(InfoKind.SUPPORT)
                    }
                } else {
                    DetectorStatus.info(InfoKind.SUPPORT)
                },
                detail = if (report.propertyAreaAvailable) {
                    null
                } else {
                    "Native property-area coverage was unavailable on this build."
                },
            ),
            CustomRomDetailRowModel(
                label = "Prop area anomalies",
                value = if (report.propertyAreaAvailable) {
                    report.propertyAreaAnomalyCount.toString()
                } else {
                    "Unavailable"
                },
                status = if (report.propertyAreaAvailable) {
                    if (report.propertyAreaAnomalyCount > 0) {
                        DetectorStatus.warning()
                    } else {
                        DetectorStatus.allClear()
                    }
                } else {
                    DetectorStatus.info(InfoKind.SUPPORT)
                },
                detail = if (report.propertyAreaAvailable) {
                    null
                } else {
                    "Native property-area coverage was unavailable on this build."
                },
            ),
            CustomRomDetailRowModel(
                label = "Prop item anomalies",
                value = if (report.propertyAreaAvailable) {
                    report.propertyAreaItemAnomalyCount.toString()
                } else {
                    "Unavailable"
                },
                status = if (report.propertyAreaAvailable) {
                    if (report.propertyAreaItemAnomalyCount > 0) {
                        DetectorStatus.warning()
                    } else {
                        DetectorStatus.allClear()
                    }
                } else {
                    DetectorStatus.info(InfoKind.SUPPORT)
                },
                detail = if (report.propertyAreaAvailable) {
                    null
                } else {
                    "Native property-area coverage was unavailable on this build."
                },
            ),
            CustomRomDetailRowModel(
                label = "Packages checked",
                value = report.checkedPackageCount.toString(),
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
            CustomRomDetailRowModel(
                label = "Package visibility",
                value = when (report.packageVisibility) {
                    CustomRomPackageVisibility.FULL -> "Full"
                    CustomRomPackageVisibility.RESTRICTED -> "Scoped"
                    CustomRomPackageVisibility.UNKNOWN -> "Unknown"
                },
                status = if (report.packageVisibility == CustomRomPackageVisibility.FULL) {
                    DetectorStatus.allClear()
                } else {
                    DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            CustomRomDetailRowModel(
                label = "Named services checked",
                value = report.checkedServiceCount.toString(),
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
            CustomRomDetailRowModel(
                label = "Services listed",
                value = report.listedServiceCount.toString(),
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
            CustomRomDetailRowModel(
                label = "Native library",
                value = if (report.nativeAvailable) "Loaded" else "Unavailable",
                status = if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
        )
    }
}

internal fun buildCleanModificationDetail(report: CustomRomReport): String {
    return buildString {
        append("Tracked property area, serial, and residual value checks were clean")
        if (report.checkedModificationPropertyCount > 0 || report.propertyAreaContextCount > 0) {
            append("; checked ")
            if (report.checkedModificationPropertyCount > 0) {
                append(report.checkedModificationPropertyCount)
                append(" tracked property name(s)")
            } else {
                append("tracked property names")
            }
        }
        if (report.propertyAreaContextCount > 0) {
            append(" across ")
            append(report.propertyAreaContextCount)
            append(" property-area context(s)")
        }
        append('.')
    }
}

internal fun methodStatus(result: CustomRomMethodResult): DetectorStatus {
    return when (result.outcome) {
        CustomRomMethodOutcome.CLEAN -> DetectorStatus.allClear()
        CustomRomMethodOutcome.DETECTED -> DetectorStatus.warning()
        CustomRomMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
    }
}
