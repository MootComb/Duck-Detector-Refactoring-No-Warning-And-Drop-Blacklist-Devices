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

package com.eltavine.duckdetector.features.dashboard.data

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.core.report.DeviceReport
import com.eltavine.duckdetector.core.report.ReportBlock
import com.eltavine.duckdetector.core.report.ReportFact
import com.eltavine.duckdetector.core.report.ReportRow
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardFindingModel
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardOverviewModel

/** Values the report banner shows, already formatted for display by the caller. */
data class ExportHeader(
    val versionName: String,
    val versionCode: Int,
    val buildHash: String,
    val buildTime: String,
    val reportTime: String,
)

data class DashboardExport(
    val header: ExportHeader,
    val overview: DashboardOverviewModel,
    val topFindings: List<DashboardFindingModel>,
    val detectors: List<DetectorReport>,
    val device: DeviceReport,
)

/**
 * Renders the plain-text scan report.
 *
 * The renderer owns the report envelope and the generic block layout; each detector owns the
 * content of its own [DetectorReport], so no detector-specific knowledge lives here.
 */
object DashboardReportRenderer {

    fun render(export: DashboardExport): String = buildString {
        appendBanner(export)
        appendExecutiveSummary(export.overview)
        appendTopFindings(export.topFindings)
        export.detectors.forEach { appendDetectorReport(it) }
        appendLine()
        appendDeviceReport(export.device)
        appendFooter()
    }

    private fun StringBuilder.appendBanner(export: DashboardExport) {
        val identity = export.device.identity
        val header = export.header
        appendLine("================================================================================")
        appendLine("                      DUCK DETECTOR — SECURITY SCAN REPORT                      ")
        appendLine("================================================================================")
        if (!identity.brand.isNullOrBlank() && !identity.model.isNullOrBlank()) {
            val osStr = if (!identity.androidRelease.isNullOrBlank()) {
                " (Android ${identity.androidRelease}, API ${identity.sdk ?: "unknown"})"
            } else {
                ""
            }
            appendLine("  Target Device  : ${identity.brand} ${identity.model}$osStr")
        }
        appendLine("  App Version    : ${header.versionName} (Build ${header.versionCode})")
        appendLine("  Build Commit   : ${header.buildHash}")
        appendLine("  Build Time     : ${header.buildTime} (UTC)")
        appendLine("  Report Time    : ${header.reportTime}")
        appendLine()
    }

    private fun StringBuilder.appendExecutiveSummary(overview: DashboardOverviewModel) {
        appendLine("--------------------------------------------------------------------------------")
        appendLine("  EXECUTIVE SUMMARY")
        appendLine("--------------------------------------------------------------------------------")
        val badge = severityBadge(overview.status.severity)
        appendLine("  Overall Status : $badge ${overview.headline}")
        appendLine("  Summary        : ${overview.summary}")
        appendLine()
        appendLine("  Scan Statistics:")
        overview.metrics.forEach { metric ->
            val icon = when (metric.label.lowercase()) {
                "danger" -> "[✖]"
                "warning" -> "[▲]"
                "ready" -> "[✔]"
                else -> "[·]"
            }
            appendLine("    $icon ${metric.label.padEnd(9)}: ${metric.value}")
        }
        appendLine()
    }

    private fun StringBuilder.appendTopFindings(findings: List<DashboardFindingModel>) {
        appendLine("--------------------------------------------------------------------------------")
        appendLine("  TOP FINDINGS")
        appendLine("--------------------------------------------------------------------------------")
        if (findings.isEmpty()) {
            appendLine("  (No security threats or warnings detected)")
        } else {
            findings.forEach { finding ->
                val badge = severityBadge(finding.status.severity)
                appendLine("  $badge ${finding.detectorTitle}")
                appendLine("    Headline : ${finding.headline}")
                if (finding.detail.isNotBlank() && finding.detail != finding.headline) {
                    appendLine("    Details  :")
                    finding.detail.trim().lines().map { it.trimEnd() }.filter { it.isNotBlank() }.forEach { line ->
                        appendLine("      $line")
                    }
                }
                appendLine()
            }
        }
    }

    private fun StringBuilder.appendDetectorReport(report: DetectorReport) {
        appendLine()
        appendLine("--------------------------------------------------------------------------------")
        appendLine("  ${severityBadge(report.severity)} ${report.title}")
        appendLine("  Verdict      : ${report.verdict}")
        appendQuickFacts(report.quickFacts)
        report.blocks.forEach { block ->
            when (block) {
                is ReportBlock.Rows -> appendRows(block.title, block.rows)
                is ReportBlock.Bullets -> appendBullets(block.title, block.items)
                is ReportBlock.Verbatim -> appendVerbatim(block)
            }
        }
    }

    private fun StringBuilder.appendQuickFacts(facts: List<ReportFact>) {
        if (facts.isEmpty()) return
        val formatted = facts.joinToString("  |  ") { "${it.label}: ${it.value}" }
        appendLine("  Quick Facts  : $formatted")
    }

    private fun StringBuilder.appendRows(title: String, rows: List<ReportRow>) {
        if (rows.isEmpty()) return
        appendLine()
        appendLine("  [$title]")
        rows.forEach { appendRow(it) }
    }

    private fun StringBuilder.appendRow(row: ReportRow) {
        val trimmedValue = row.value.trim()
        val hasValue = trimmedValue.isNotBlank()
        val trimmedDetail = row.detail?.trim()
        val hasDetail = !trimmedDetail.isNullOrBlank() && trimmedDetail != trimmedValue

        if (!hasValue && !hasDetail) {
            appendLine("    • ${row.label}")
            return
        }

        if (!hasValue && hasDetail) {
            appendLine("    • ${row.label}")
            appendDetailLines(trimmedDetail)
            return
        }

        if (!hasDetail) {
            appendLine("    • ${row.label}: $trimmedValue")
            return
        }

        val detailLines = trimmedDetail.lines().map { it.trimEnd() }.filter { it.isNotBlank() }
        if (detailLines.size == 1 && detailLines[0].length <= 60 && !detailLines[0].contains(" = ") && !detailLines[0].contains(" | ")) {
            appendLine("    • ${row.label}: $trimmedValue (${detailLines[0]})")
        } else {
            appendLine("    • ${row.label}: $trimmedValue")
            detailLines.forEach { line ->
                appendLine("        $line")
            }
        }
    }

    private fun StringBuilder.appendDetailLines(detail: String) {
        detail.lines().map { it.trimEnd() }.filter { it.isNotBlank() }.forEach { line ->
            appendLine("        $line")
        }
    }

    private fun StringBuilder.appendBullets(title: String, items: List<String>) {
        if (items.isEmpty()) return
        appendLine()
        appendLine("  [$title]")
        items.forEach { text ->
            val lines = text.trim().lines().map { it.trimEnd() }.filter { it.isNotBlank() }
            if (lines.isNotEmpty()) {
                appendLine("    • ${lines.first()}")
                lines.drop(1).forEach { line ->
                    appendLine("      $line")
                }
            }
        }
    }

    private fun StringBuilder.appendVerbatim(block: ReportBlock.Verbatim) {
        appendLine()
        appendLine("  [${block.title}]")
        block.lines.forEach { appendLine(it) }
    }

    private fun StringBuilder.appendDeviceReport(device: DeviceReport) {
        appendLine()
        appendLine("================================================================================")
        appendLine("  DEVICE & SYSTEM SPECIFICATIONS")
        appendLine("================================================================================")
        appendQuickFacts(device.quickFacts)
        device.sections.forEach { appendVerbatim(it) }
    }

    private fun StringBuilder.appendFooter() {
        appendLine()
        appendLine("================================================================================")
        appendLine("                                 END OF REPORT                                  ")
        appendLine("================================================================================")
    }

    private fun severityBadge(severity: DetectionSeverity): String = when (severity) {
        DetectionSeverity.DANGER -> "[✖ DANGER]"
        DetectionSeverity.WARNING -> "[▲ WARNING]"
        DetectionSeverity.INFO -> "[ℹ INFO]"
        DetectionSeverity.ALL_CLEAR -> "[✔ CLEAR]"
    }
}
