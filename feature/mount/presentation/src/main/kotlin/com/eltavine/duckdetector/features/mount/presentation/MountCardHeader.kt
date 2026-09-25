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

package com.eltavine.duckdetector.features.mount.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.mount.domain.MountFindingSeverity
import com.eltavine.duckdetector.features.mount.domain.MountReport
import com.eltavine.duckdetector.features.mount.domain.MountStage
import com.eltavine.duckdetector.features.mount.presentation.model.MountHeaderFactModel

internal fun buildSubtitle(report: MountReport): String {
    return when (report.stage) {
        MountStage.LOADING -> "mounts + mountinfo + maps + statfs + statx"
        MountStage.FAILED -> "local mount scan failed"
        MountStage.READY -> "${report.mountEntryCount} mounts · ${report.mountInfoEntryCount} mountinfo · ${report.mapLineCount} map lines"
    }
}

internal fun buildVerdict(report: MountReport): String {
    return when (report.stage) {
        MountStage.LOADING -> "Scanning runtime mount visibility"
        MountStage.FAILED -> when {
            report.dangerSignalCount > 0 -> "${report.dangerSignalCount} critical mount signal(s)"
            report.warningSignalCount > 0 -> "${report.warningSignalCount} mount signal(s) need review"
            else -> "Mount scan failed"
        }
        MountStage.READY -> when {
            report.dangerSignalCount > 0 && hasOnlyPreloadEvidence(report) ->
                "${report.dangerSignalCount} critical startup signal(s)"

            report.dangerSignalCount > 0 -> "${report.dangerSignalCount} critical mount signal(s)"
            report.warningSignalCount > 0 && hasOnlyPreloadEvidence(report) ->
                "${report.warningSignalCount} startup signal(s) need review"

            report.warningSignalCount > 0 -> "${report.warningSignalCount} mount signal(s) need review"
            else -> "No suspicious mount-layer signal"
        }
    }
}

internal fun buildSummary(report: MountReport): String {
    return when (report.stage) {
        MountStage.LOADING ->
            "Mount table, mountinfo, memory maps, filesystem type, and path-based root artifact probes are collecting local evidence."

        MountStage.FAILED -> when {
            report.zygoteNext.leakDetected ->
                "The Android 17 zygote_next mount view exposed root-managed mount records."

            report.procMountViewTokenHit ->
                "A visible process mount table contains a direct root-managed mount token."

            report.procMountViewDivergent ->
                "Cross-process mount tables diverge from the isolated-process baseline."

            else -> report.errorMessage ?: "Mount scan failed before evidence could be assembled."
        }

        MountStage.READY -> if (report.zygoteNext.leakDetected) {
            "The Android 17 zygote_next native isolated-service path exposed root-managed mount records."
        } else if (report.procMountViewTokenHit) {
            "A visible process mount table contains a direct root-managed mount token."
        } else if (report.procMountViewDivergent) {
            "Cross-process mount tables diverge from the isolated-process baseline."
        } else if (hasOnlyPreloadEvidence(report) && report.dangerFindings.isNotEmpty()) {
            "Startup preload captured early namespace or mount anomalies before the normal runtime scan settled."
        } else if (hasOnlyPreloadEvidence(report) && report.warningFindings.isNotEmpty()) {
            "Startup preload captured weaker early mount inconsistencies that still merit review."
        } else when {
            report.dangerFindings.isNotEmpty() ->
                "The current app mount view contains root-managed overlays, writable-system behavior, selective shell-tmp concealment, hidden mount inconsistencies, or strong runtime artifacts."

            report.warningFindings.isNotEmpty() ->
                "The mount layer is not obviously compromised, but it still contains review-worthy runtime or filesystem drift."

            else ->
                "No suspicious Magisk, overlay, writable-system, or mount-coherence artifact surfaced from the current app context."
        }
    }
}

internal fun buildHeaderFacts(report: MountReport): List<MountHeaderFactModel> {
    return when (report.stage) {
        MountStage.LOADING -> placeholderFacts("Pending", DetectorStatus.info(InfoKind.SUPPORT))
        MountStage.FAILED -> if (report.dangerSignalCount > 0 || report.warningSignalCount > 0) {
            listOf(
                MountHeaderFactModel(
                    label = "Critical",
                    value = countLabel(report.dangerSignalCount),
                    status = if (report.dangerSignalCount == 0) {
                        DetectorStatus.allClear()
                    } else {
                        DetectorStatus.danger()
                    },
                ),
                MountHeaderFactModel(
                    label = "Review",
                    value = countLabel(report.warningSignalCount),
                    status = if (report.warningSignalCount == 0) {
                        DetectorStatus.allClear()
                    } else {
                        DetectorStatus.warning()
                    },
                ),
                MountHeaderFactModel("Coverage", "Error", DetectorStatus.info(InfoKind.ERROR)),
                MountHeaderFactModel("Native", "Error", DetectorStatus.info(InfoKind.ERROR)),
            )
        } else {
            placeholderFacts("Error", DetectorStatus.info(InfoKind.ERROR))
        }
        MountStage.READY -> listOf(
            MountHeaderFactModel(
                label = "Critical",
                value = countLabel(report.dangerSignalCount),
                status = if (report.dangerSignalCount == 0) DetectorStatus.allClear() else DetectorStatus.danger(),
            ),
            MountHeaderFactModel(
                label = "Review",
                value = countLabel(report.warningSignalCount),
                status = if (report.warningSignalCount == 0) DetectorStatus.allClear() else DetectorStatus.warning(),
            ),
            MountHeaderFactModel(
                label = "Coverage",
                value = "${coveragePercent(report)}%",
                status = when {
                    report.permissionDenied == 0 -> DetectorStatus.allClear()
                    report.permissionDenied * 2 >= report.permissionTotal && report.permissionTotal > 0 -> DetectorStatus.warning()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            MountHeaderFactModel(
                label = "Native",
                value = if (report.nativeAvailable) "Loaded" else "N/A",
                status = if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
        )
    }
}

private fun placeholderFacts(
    value: String,
    status: DetectorStatus
): List<MountHeaderFactModel> {
    return listOf(
        MountHeaderFactModel("Critical", value, status),
        MountHeaderFactModel("Review", value, status),
        MountHeaderFactModel("Coverage", value, status),
        MountHeaderFactModel("Native", value, status),
    )
}

private fun countLabel(count: Int): String = if (count == 0) "None" else count.toString()

private fun hasOnlyPreloadEvidence(report: MountReport): Boolean {
    if (report.zygoteNext.leakDetected ||
        report.procMountViewTokenHit ||
        report.procMountViewDivergent
    ) {
        return false
    }
    val findings = report.findings.filter {
        it.severity == MountFindingSeverity.DANGER || it.severity == MountFindingSeverity.WARNING
    }
    return findings.isNotEmpty() && findings.all { it.id.startsWith("early_preload_") }
}
