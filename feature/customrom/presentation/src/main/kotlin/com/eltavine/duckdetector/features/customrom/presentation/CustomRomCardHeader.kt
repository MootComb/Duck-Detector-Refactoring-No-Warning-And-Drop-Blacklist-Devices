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
import com.eltavine.duckdetector.features.customrom.domain.CustomRomPackageVisibility
import com.eltavine.duckdetector.features.customrom.domain.CustomRomReport
import com.eltavine.duckdetector.features.customrom.domain.CustomRomStage
import com.eltavine.duckdetector.features.customrom.presentation.model.CustomRomHeaderFactModel

internal fun buildSubtitle(report: CustomRomReport): String {
    return when (report.stage) {
        CustomRomStage.LOADING -> "properties + prop integrity + packages + services + native traces"
        CustomRomStage.FAILED -> "local aftermarket firmware probe failed"
        CustomRomStage.READY -> buildString {
            append("${report.checkedPropertyCount} props · ")
            if (report.propertyAreaAvailable) {
                append("${report.checkedModificationPropertyCount} mod props")
            } else {
                append("mod props unavailable")
            }
            append(" · ${report.checkedPackageCount} packages · ${report.checkedServiceCount} named services")
        }
    }
}

internal fun buildVerdict(report: CustomRomReport): String {
    return when (report.stage) {
        CustomRomStage.LOADING -> "Scanning aftermarket firmware signals"
        CustomRomStage.FAILED -> "Custom ROM scan failed"
        CustomRomStage.READY -> buildVerdictBody(report)
    }
}

internal fun buildSummary(report: CustomRomReport): String {
    return when (report.stage) {
        CustomRomStage.LOADING ->
            "System properties, prop integrity, runtime packages/services, framework traces, and resource map checks are collecting local firmware evidence."

        CustomRomStage.FAILED ->
            report.errorMessage ?: "Custom ROM scan failed before evidence could be assembled."

        CustomRomStage.READY -> when {
            report.hasIndicators ->
                "Build properties, property-area integrity, bootloader state, runtime packages or services, framework traces, native symbol traces, or resource map anomalies indicate aftermarket firmware, resetprop-style changes, or an unlocked boot chain."

            !report.nativeAvailable ->
                "Native coverage was unavailable on this build, so only Java-side probes were used."

            report.hasReducedCoverage() ->
                "Available probes were clean, but package visibility, property-area, or native symbol coverage was incomplete on this build."

            else ->
                "No common custom ROM branding, property-area, service, package, framework trace, native symbol trace, or resource map anomaly surfaced from local probes."
        }
    }
}

internal fun buildHeaderFacts(report: CustomRomReport): List<CustomRomHeaderFactModel> {
    return when (report.stage) {
        CustomRomStage.LOADING -> placeholderFacts(
            "Pending",
            DetectorStatus.info(InfoKind.SUPPORT)
        )

        CustomRomStage.FAILED -> placeholderFacts("Error", DetectorStatus.info(InfoKind.ERROR))
        CustomRomStage.READY -> listOf(
            CustomRomHeaderFactModel(
                label = "ROMs",
                value = detectedRomValue(report),
                status = when {
                    report.detectedRoms.isNotEmpty() -> DetectorStatus.warning()
                    report.hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.allClear()
                },
            ),
            CustomRomHeaderFactModel(
                label = "Build",
                value = when {
                    report.buildSignalCount + report.modificationSignalCount > 0 ->
                        signalValue(report.buildSignalCount + report.modificationSignalCount)

                    !report.propertyAreaAvailable -> "Unavailable"

                    else -> "None"
                },
                status = when {
                    report.buildSignalCount + report.modificationSignalCount > 0 ->
                        DetectorStatus.warning()

                    !report.propertyAreaAvailable -> DetectorStatus.info(InfoKind.SUPPORT)

                    else -> DetectorStatus.allClear()
                },
            ),
            CustomRomHeaderFactModel(
                label = "Runtime",
                value = when {
                    report.runtimeSignalCount > 0 -> report.runtimeSignalCount.toString()
                    report.packageVisibility == CustomRomPackageVisibility.RESTRICTED -> "Scoped"
                    report.packageVisibility == CustomRomPackageVisibility.UNKNOWN -> "Unavailable"
                    else -> "None"
                },
                status = when {
                    report.runtimeSignalCount > 0 -> DetectorStatus.warning()
                    report.packageVisibility != CustomRomPackageVisibility.FULL -> DetectorStatus.info(
                        InfoKind.SUPPORT
                    )

                    else -> DetectorStatus.allClear()
                },
            ),
            CustomRomHeaderFactModel(
                label = "Native",
                value = when {
                    !report.nativeAvailable -> "N/A"
                    report.nativeSignalCount > 0 -> report.nativeSignalCount.toString()
                    else -> "None"
                },
                status = when {
                    report.nativeSignalCount > 0 -> DetectorStatus.warning()
                    !report.nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
                    report.hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.allClear()
                },
            ),
        )
    }
}

internal fun placeholderFacts(
    value: String,
    status: DetectorStatus,
): List<CustomRomHeaderFactModel> {
    return listOf(
        CustomRomHeaderFactModel("ROMs", value, status),
        CustomRomHeaderFactModel("Build", value, status),
        CustomRomHeaderFactModel("Runtime", value, status),
        CustomRomHeaderFactModel("Native", value, status),
    )
}

internal fun detectedRomValue(report: CustomRomReport): String {
    return when {
        report.detectedRoms.isEmpty() -> "None"
        report.detectedRoms.size <= 2 -> report.detectedRoms.joinToString("/")
        else -> report.detectedRoms.take(2)
            .joinToString("/") + " +${report.detectedRoms.size - 2}"
    }
}

internal fun signalValue(count: Int): String {
    return if (count > 0) count.toString() else "None"
}

internal fun buildVerdictBody(report: CustomRomReport): String {
    val verdictParts = buildList {
        if (report.detectedRoms.isNotEmpty()) {
            add(
                if (report.detectedRoms.size == 1) {
                    "${report.detectedRoms.first()} signature"
                } else {
                    "${report.detectedRoms.size} ROM signatures"
                }
            )
        }
        if (report.modificationFindings.isNotEmpty()) {
            add("${report.modificationFindings.size} modification signal(s)")
        }
        if (report.symbolFindings.isNotEmpty()) {
            add("${report.symbolFindings.size} native symbol trace(s)")
        }
    }

    return when {
        verdictParts.isNotEmpty() -> "${verdictParts.joinToString(separator = " + ")} detected"
        report.hasReducedCoverage() -> "Custom ROM scan has reduced coverage"
        else -> "No custom ROM signatures"
    }
}

internal fun CustomRomReport.hasReducedCoverage(): Boolean {
    return !nativeAvailable ||
            !propertyAreaAvailable ||
            !symbolScanAvailable ||
            packageVisibility != CustomRomPackageVisibility.FULL
}
