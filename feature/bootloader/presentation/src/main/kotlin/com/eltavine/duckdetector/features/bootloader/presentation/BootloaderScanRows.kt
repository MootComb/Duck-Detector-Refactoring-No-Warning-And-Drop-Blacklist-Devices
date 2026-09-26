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

package com.eltavine.duckdetector.features.bootloader.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingGroup
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderReport
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderStage
import com.eltavine.duckdetector.features.bootloader.presentation.model.BootloaderDetailRowModel

internal fun buildScanRows(report: BootloaderReport): List<BootloaderDetailRowModel> {
    return when (report.stage) {
        BootloaderStage.LOADING -> placeholderRows(
            scanPlaceholders(),
            "Pending",
            DetectorStatus.info(InfoKind.SUPPORT)
        )

        BootloaderStage.FAILED -> placeholderRows(
            scanPlaceholders(),
            "Error",
            DetectorStatus.info(InfoKind.ERROR)
        )

        BootloaderStage.READY -> listOf(
            BootloaderDetailRowModel(
                label = "Properties checked",
                value = report.checkedPropertyCount.toString(),
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
            BootloaderDetailRowModel(
                label = "Properties observed",
                value = report.observedPropertyCount.toString(),
                status = if (report.observedPropertyCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            BootloaderDetailRowModel(
                label = "Native hits",
                value = report.nativePropertyHitCount.toString(),
                status = if (report.nativePropertyHitCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            BootloaderDetailRowModel(
                label = "Raw boot hits",
                value = report.rawBootParamHitCount.toString(),
                status = if (report.rawBootParamHitCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            BootloaderDetailRowModel(
                label = "Source mismatches",
                value = report.sourceMismatchCount.toString(),
                status = if (report.sourceMismatchCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
            ),
            BootloaderDetailRowModel(
                label = "Cross-checks",
                value = report.consistencyFindingCount.toString(),
                status = if (report.consistencyFindingCount > 0) {
                    if (report.dangerFindings.any { it.group == BootloaderFindingGroup.CONSISTENCY }) {
                        DetectorStatus.danger()
                    } else {
                        DetectorStatus.warning()
                    }
                } else {
                    DetectorStatus.allClear()
                },
            ),
            BootloaderDetailRowModel(
                label = "Attestation chain",
                value = report.attestationChainLength.toString(),
                status = when {
                    report.attestationChainLength == 0 -> DetectorStatus.danger()
                    report.attestationAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            BootloaderDetailRowModel(
                label = "Hardware-backed",
                value = if (report.hardwareBacked) "Yes" else "No",
                status = if (report.hardwareBacked) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
        )
    }
}

internal fun placeholderRows(
    labels: List<String>,
    value: String,
    status: DetectorStatus,
): List<BootloaderDetailRowModel> {
    return labels.map { label ->
        BootloaderDetailRowModel(
            label = label,
            value = value,
            status = status,
        )
    }
}

private fun scanPlaceholders(): List<String> = listOf(
    "Properties checked",
    "Properties observed",
    "Native hits",
    "Raw boot hits",
    "Source mismatches",
    "Cross-checks",
    "Attestation chain",
    "Hardware-backed",
)
