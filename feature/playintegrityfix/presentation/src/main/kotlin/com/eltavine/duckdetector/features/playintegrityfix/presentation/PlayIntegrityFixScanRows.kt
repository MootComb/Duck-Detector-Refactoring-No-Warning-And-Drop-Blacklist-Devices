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

package com.eltavine.duckdetector.features.playintegrityfix.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixReport
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixSignalSeverity
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixStage
import com.eltavine.duckdetector.features.playintegrityfix.presentation.model.PlayIntegrityFixDetailRowModel

internal fun buildScanRows(report: PlayIntegrityFixReport): List<PlayIntegrityFixDetailRowModel> {
    return when (report.stage) {
        PlayIntegrityFixStage.LOADING -> placeholderRows(
            labels = listOf(
                "Properties checked",
                "Property hits",
                "Reflection hits",
                "getprop hits",
                "JVM hits",
                "Native prop hits",
                "Native traces",
                "Native library",
            ),
            status = DetectorStatus.info(InfoKind.SUPPORT),
            value = "Pending",
        )

        PlayIntegrityFixStage.FAILED -> placeholderRows(
            labels = listOf(
                "Properties checked",
                "Property hits",
                "Reflection hits",
                "getprop hits",
                "JVM hits",
                "Native prop hits",
                "Native traces",
                "Native library",
            ),
            status = DetectorStatus.info(InfoKind.ERROR),
            value = "Error",
        )

        PlayIntegrityFixStage.READY -> listOf(
            PlayIntegrityFixDetailRowModel(
                label = "Properties checked",
                value = report.checkedPropertyCount.toString(),
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
            PlayIntegrityFixDetailRowModel(
                label = "Property hits",
                value = report.directPropertyCount.toString(),
                status = propertyStatus(report),
            ),
            PlayIntegrityFixDetailRowModel(
                label = "Reflection hits",
                value = report.reflectionHitCount.toString(),
                status = if (report.reflectionHitCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            PlayIntegrityFixDetailRowModel(
                label = "getprop hits",
                value = report.getpropHitCount.toString(),
                status = if (report.getpropHitCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            PlayIntegrityFixDetailRowModel(
                label = "JVM hits",
                value = report.jvmHitCount.toString(),
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
            PlayIntegrityFixDetailRowModel(
                label = "Native prop hits",
                value = report.nativePropertyHitCount.toString(),
                status = when {
                    report.nativePropertyHitCount > 0 -> DetectorStatus.warning()
                    report.nativeAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            PlayIntegrityFixDetailRowModel(
                label = "Native traces",
                value = report.nativeTraceCount.toString(),
                status = when {
                    report.nativeSignals.any { it.severity == PlayIntegrityFixSignalSeverity.DANGER } -> DetectorStatus.danger()
                    report.nativeTraceCount > 0 -> DetectorStatus.warning()
                    report.nativeAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            PlayIntegrityFixDetailRowModel(
                label = "Native library",
                value = if (report.nativeAvailable) "Loaded" else "Unavailable",
                status = if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
        )
    }
}

internal fun placeholderRows(
    labels: List<String>,
    status: DetectorStatus,
    value: String,
    monospace: Boolean = false,
): List<PlayIntegrityFixDetailRowModel> {
    return labels.map { label ->
        PlayIntegrityFixDetailRowModel(
            label = label,
            value = value,
            status = status,
            detailMonospace = monospace,
        )
    }
}

internal fun propertyStatus(report: PlayIntegrityFixReport): DetectorStatus {
    return when {
        report.propertySignals.any { it.severity == PlayIntegrityFixSignalSeverity.DANGER } -> DetectorStatus.danger()
        report.propertySignals.any { it.severity == PlayIntegrityFixSignalSeverity.WARNING } -> DetectorStatus.warning()
        else -> DetectorStatus.allClear()
    }
}
