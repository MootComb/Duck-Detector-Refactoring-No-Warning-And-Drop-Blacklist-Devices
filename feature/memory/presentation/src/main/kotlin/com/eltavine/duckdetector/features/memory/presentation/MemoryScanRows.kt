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

package com.eltavine.duckdetector.features.memory.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.memory.domain.MemoryReport
import com.eltavine.duckdetector.features.memory.domain.MemoryStage
import com.eltavine.duckdetector.features.memory.presentation.model.MemoryDetailRowModel

internal fun buildScanRows(report: MemoryReport): List<MemoryDetailRowModel> {
    return when (report.stage) {
        MemoryStage.LOADING -> placeholderRows(
            listOf(
                "Danger findings",
                "Review findings",
                "Modified functions",
                "Native library"
            ),
            DetectorStatus.info(InfoKind.SUPPORT),
            "Pending",
        )

        MemoryStage.FAILED -> placeholderRows(
            listOf(
                "Danger findings",
                "Review findings",
                "Modified functions",
                "Native library"
            ),
            DetectorStatus.info(InfoKind.ERROR),
            "Error",
        )

        MemoryStage.READY -> listOf(
            MemoryDetailRowModel(
                label = "Danger findings",
                value = if (report.nativeAvailable || report.dangerFindingCount > 0) {
                    report.dangerFindingCount.toString()
                } else {
                    "N/A"
                },
                status = when {
                    report.dangerFindingCount > 0 -> DetectorStatus.danger()
                    report.nativeAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            MemoryDetailRowModel(
                label = "Review findings",
                value = if (report.nativeAvailable || report.reviewFindingCount > 0) {
                    report.reviewFindingCount.toString()
                } else {
                    "N/A"
                },
                status = when {
                    report.reviewFindingCount > 0 -> DetectorStatus.warning()
                    report.nativeAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            MemoryDetailRowModel(
                label = "Modified functions",
                value = if (report.nativeAvailable || report.modifiedFunctionCount > 0) {
                    report.modifiedFunctionCount.toString()
                } else {
                    "N/A"
                },
                status = when {
                    report.modifiedFunctionCount > 0 -> DetectorStatus.warning()
                    report.nativeAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            MemoryDetailRowModel(
                label = "Native library",
                value = if (report.nativeAvailable) "Loaded" else "Unavailable",
                status = if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.ERROR
                ),
            ),
        )
    }
}

internal fun placeholderRows(
    labels: List<String>,
    status: DetectorStatus,
    value: String,
): List<MemoryDetailRowModel> {
    return labels.map { label ->
        MemoryDetailRowModel(
            label = label,
            value = value,
            status = status,
        )
    }
}
