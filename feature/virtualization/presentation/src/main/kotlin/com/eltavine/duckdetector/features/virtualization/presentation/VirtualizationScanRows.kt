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

package com.eltavine.duckdetector.features.virtualization.presentation

import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationReport
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationStage
import com.eltavine.duckdetector.features.virtualization.presentation.model.VirtualizationDetailRowModel

internal fun buildScanRows(report: VirtualizationReport): List<VirtualizationDetailRowModel> {
    return when (report.stage) {
        VirtualizationStage.LOADING -> placeholderRows(
            SCAN_LABELS,
            "Pending",
            DetectorStatus.info(InfoKind.SUPPORT),
        )

        VirtualizationStage.FAILED -> placeholderRows(
            SCAN_LABELS,
            "Error",
            DetectorStatus.info(InfoKind.ERROR),
        )

        VirtualizationStage.READY -> listOf(
            VirtualizationDetailRowModel(
                label = "Startup preload",
                value = if (report.startupPreloadAvailable) "Ready" else "Unavailable",
                status = if (report.startupPreloadAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT,
                ),
            ),
            VirtualizationDetailRowModel(
                label = "Preload context",
                value = yesNo(report.startupPreloadContextValid),
                status = if (report.startupPreloadContextValid) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT,
                ),
            ),
            VirtualizationDetailRowModel(
                label = "Cross-process helper",
                value = if (report.crossProcessAvailable) "Ready" else "Unavailable",
                status = if (report.crossProcessAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT,
                ),
            ),
            VirtualizationDetailRowModel(
                label = "Isolated helper",
                value = if (report.isolatedProcessAvailable) "Ready" else "Unavailable",
                status = if (report.isolatedProcessAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT,
                ),
            ),
            VirtualizationDetailRowModel(
                label = "Package visibility",
                value = when (report.packageVisibility) {
                    InstalledPackageVisibility.FULL -> "Full"
                    InstalledPackageVisibility.RESTRICTED -> "Scoped"
                    InstalledPackageVisibility.UNKNOWN -> "Unknown"
                },
                status = if (report.packageVisibility != InstalledPackageVisibility.FULL) {
                    DetectorStatus.info(InfoKind.SUPPORT)
                } else {
                    DetectorStatus.allClear()
                },
            ),
            VirtualizationDetailRowModel(
                label = "Maps scanned",
                value = report.mapLineCount.toString(),
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
            VirtualizationDetailRowModel(
                label = "FD entries",
                value = report.fdCount.toString(),
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
            VirtualizationDetailRowModel(
                label = "Mountinfo lines",
                value = report.mountInfoCount.toString(),
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
            VirtualizationDetailRowModel(
                label = "EGL renderer",
                value = if (report.eglAvailable) "Ready" else "Unavailable",
                status = if (report.eglAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT,
                ),
            ),
            VirtualizationDetailRowModel(
                label = "Dex paths",
                value = report.dexPathEntryCount.toString(),
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
            VirtualizationDetailRowModel(
                label = "Dex path hits",
                value = report.dexPathHitCount.toString(),
                status = severityStatus(report.dexPathHitCount),
            ),
            VirtualizationDetailRowModel(
                label = "UID identity hits",
                value = report.uidIdentityHitCount.toString(),
                status = severityStatus(report.uidIdentityHitCount),
            ),
            VirtualizationDetailRowModel(
                label = "Mount namespace",
                value = if (report.mountNamespaceAvailable) "Ready" else "Unavailable",
                status = if (report.mountNamespaceAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT,
                ),
            ),
            VirtualizationDetailRowModel(
                label = "Mount anchor drift",
                value = report.mountAnchorDriftCount.toString(),
                status = severityStatus(report.mountAnchorDriftCount),
            ),
            VirtualizationDetailRowModel(
                label = "Environment hits",
                value = report.environmentHitCount.toString(),
                status = severityStatus(report.environmentHitCount),
            ),
            VirtualizationDetailRowModel(
                label = "Translation hits",
                value = report.translationHitCount.toString(),
                status = severityStatus(report.translationHitCount),
            ),
            VirtualizationDetailRowModel(
                label = "Runtime hits",
                value = report.runtimeArtifactHitCount.toString(),
                status = severityStatus(report.runtimeArtifactHitCount),
            ),
            VirtualizationDetailRowModel(
                label = "Consistency hits",
                value = report.consistencyHitCount.toString(),
                status = severityStatus(report.consistencyHitCount),
            ),
            VirtualizationDetailRowModel(
                label = "Isolated consistency",
                value = report.isolatedConsistencyHitCount.toString(),
                status = severityStatus(report.isolatedConsistencyHitCount),
            ),
            VirtualizationDetailRowModel(
                label = "Honeypot hits",
                value = report.honeypotHitCount.toString(),
                status = severityStatus(report.honeypotHitCount),
            ),
            VirtualizationDetailRowModel(
                label = "Syscall pack",
                value = if (report.syscallPackSupported) "Ready" else "Unsupported",
                status = if (report.syscallPackSupported) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT,
                ),
            ),
            VirtualizationDetailRowModel(
                label = "Syscall pack hits",
                value = report.syscallPackHitCount.toString(),
                status = severityStatus(report.syscallPackHitCount),
            ),
        )
    }
}

internal fun placeholderRows(
    labels: List<String>,
    value: String,
    status: DetectorStatus,
): List<VirtualizationDetailRowModel> {
    return labels.map { label ->
        VirtualizationDetailRowModel(label = label, value = value, status = status)
    }
}

private fun yesNo(value: Boolean): String = if (value) "Yes" else "No"

private fun severityStatus(count: Int): DetectorStatus {
    return if (count > 0) DetectorStatus.warning() else DetectorStatus.allClear()
}

private val SCAN_LABELS = listOf(
    "Startup preload",
    "Preload context",
    "Cross-process helper",
    "Isolated helper",
    "Package visibility",
    "Maps scanned",
    "FD entries",
    "Mountinfo lines",
    "EGL renderer",
    "Dex paths",
    "Dex path hits",
    "UID identity hits",
    "Mount namespace",
    "Mount anchor drift",
    "Environment hits",
    "Translation hits",
    "Runtime hits",
    "Consistency hits",
    "Isolated consistency",
    "Honeypot hits",
    "Syscall pack",
    "Syscall pack hits",
)
