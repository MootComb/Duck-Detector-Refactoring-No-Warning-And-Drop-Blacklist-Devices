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

package com.eltavine.duckdetector.features.dashboard.ui.model

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.core.scan.DetectorSummary
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

data class DashboardOverviewMetricModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class DashboardOverviewModel(
    val title: String,
    val headline: String,
    val summary: String,
    val status: DetectorStatus,
    val metrics: List<DashboardOverviewMetricModel>,
    val showTitleIcon: Boolean = false,
)

data class DashboardFindingModel(
    val detectorTitle: String,
    val headline: String,
    val detail: String,
    val status: DetectorStatus,
)

data class DashboardUiState(
    val overview: DashboardOverviewModel,
    val topFindings: List<DashboardFindingModel>,
    /** Detector cards in display order: most severe first, then by title. */
    val cardOrder: List<DetectorId>,
    val isLoading: Boolean,
)

fun buildDashboardOverview(
    contributions: List<DetectorSummary>,
    scanDurationMillis: Long? = null,
    scanCompletedAtEpochMillis: Long? = null,
): DashboardOverviewModel {
    val total = contributions.size
    val readyCount = contributions.count { it.ready }
    val pendingCount = total - readyCount
    val dangerCount = contributions.count { it.status.severity == DetectionSeverity.DANGER }
    val warningCount = contributions.count { it.status.severity == DetectionSeverity.WARNING }
    val infoErrorCount = contributions.count {
        it.status.severity == DetectionSeverity.INFO && it.status.infoKind == InfoKind.ERROR
    }

    val focusTitles = prioritizedContributions(contributions)
        .take(2)
        .map { it.title }

    val overviewStatus = when {
        dangerCount > 0 -> DetectorStatus.danger()
        warningCount > 0 -> DetectorStatus.warning()
        infoErrorCount > 0 -> DetectorStatus.info(InfoKind.ERROR)
        readyCount == 0 -> DetectorStatus.info(InfoKind.SUPPORT)
        pendingCount > 0 -> DetectorStatus.info(InfoKind.SUPPORT)
        else -> DetectorStatus.allClear()
    }

    val headline = when {
        dangerCount > 0 -> "Danger"
        warningCount > 0 -> "Warning"
        infoErrorCount > 0 -> "Info"
        readyCount == 0 -> "Ready"
        pendingCount > 0 -> "Pending"
        else -> "OK"
    }

    val summary = when {
        dangerCount > 0 -> "Start with ${focusTitles.joinToString(separator = " and ")}."
        warningCount > 0 -> "Review ${focusTitles.joinToString(separator = " and ")} next."
        infoErrorCount > 0 -> "${focusTitles.joinToString(separator = " and ")} need more context before treating results as clean."
        readyCount == 0 -> "Detector cards will populate as local checks complete."
        pendingCount > 0 -> "Additional modules are still collecting their local evidence."
        else -> "Use the detector cards below to inspect local evidence in detail."
    }

    return DashboardOverviewModel(
        title = if (scanDurationMillis != null && scanCompletedAtEpochMillis != null && pendingCount == 0) {
            "Scanned at ${formatDetectedTimeLocal(scanCompletedAtEpochMillis)}\nTotal time ${formatScanDuration(scanDurationMillis)}"
        } else {
            "Security overview"
        },
        headline = headline,
        summary = summary,
        status = overviewStatus,
        metrics = listOf(
            DashboardOverviewMetricModel(
                label = "Danger",
                value = dangerCount.toString(),
                status = if (dangerCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
            ),
            DashboardOverviewMetricModel(
                label = "Warning",
                value = warningCount.toString(),
                status = if (warningCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
            ),
            DashboardOverviewMetricModel(
                label = "Ready",
                value = readyCount.toString(),
                status = if (readyCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            DashboardOverviewMetricModel(
                label = "Pending",
                value = pendingCount.toString(),
                status = if (pendingCount > 0) DetectorStatus.info(InfoKind.SUPPORT) else DetectorStatus.allClear(),
            ),
        ),
        showTitleIcon = scanDurationMillis != null && pendingCount == 0,
    )
}

private fun formatDetectedTimeLocal(epochMillis: Long): String {
    val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.US)
    return Instant.ofEpochMilli(epochMillis)
        .atZone(ZoneId.systemDefault())
        .format(formatter)
}

private fun formatScanDuration(
    durationMillis: Long,
): String {
    return when {
        durationMillis < 1_000L -> "${durationMillis}ms"
        durationMillis < 10_000L -> String.format(Locale.US, "%.1fs", durationMillis / 1_000f)
        else -> "${(durationMillis + 500L) / 1_000L}s"
    }
}

fun buildDashboardFindings(
    contributions: List<DetectorSummary>,
): List<DashboardFindingModel> {
    val prioritized = prioritizedContributions(contributions)
    val attentionFindings = prioritized.filter { contribution ->
        when (contribution.status.severity) {
            DetectionSeverity.DANGER,
            DetectionSeverity.WARNING -> true

            DetectionSeverity.INFO -> contribution.status.infoKind == InfoKind.ERROR
            DetectionSeverity.ALL_CLEAR -> false
        }
    }
    if (attentionFindings.isNotEmpty()) {
        return attentionFindings.take(3).map { contribution ->
            DashboardFindingModel(
                detectorTitle = contribution.title,
                headline = contribution.headline,
                detail = contribution.findingDetail ?: contribution.summary,
                status = contribution.status,
            )
        }
    }

    if (contributions.any { !it.ready }) {
        return listOf(
            DashboardFindingModel(
                detectorTitle = "Scan status",
                headline = "Waiting for detector evidence",
                detail = "Detector cards will expand as modules finish collecting local evidence.",
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
        )
    }

    return listOf(
        DashboardFindingModel(
            detectorTitle = "Overview",
            headline = "No urgent findings in ready modules",
            detail = "Open detector cards below to review detailed local evidence and secondary checks.",
            status = DetectorStatus.allClear(),
        ),
    )
}

private fun prioritizedContributions(
    contributions: List<DetectorSummary>,
): List<DetectorSummary> {
    return contributions.sortedWith(
        compareBy<DetectorSummary> { contribution ->
            detectorPriority(contribution.status)
        }.thenBy { if (it.ready) 0 else 1 }
            .thenBy { it.title },
    )
}

fun dashboardCardOrder(
    summaries: List<DetectorSummary>,
): List<DetectorId> {
    return summaries.sortedWith(
        compareBy<DetectorSummary> { summary ->
            detectorPriority(summary.status)
        }.thenBy { summary -> summary.title },
    ).map { it.id }
}

private fun detectorPriority(
    status: DetectorStatus,
): Int {
    return when (status.severity) {
        DetectionSeverity.DANGER -> 0
        DetectionSeverity.WARNING -> 1
        DetectionSeverity.INFO -> if (status.infoKind == InfoKind.ERROR) 2 else 3
        DetectionSeverity.ALL_CLEAR -> 4
    }
}
