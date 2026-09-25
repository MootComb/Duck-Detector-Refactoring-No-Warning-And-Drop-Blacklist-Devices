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

package com.eltavine.duckdetector.features.tee.presentation

import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.core.report.ReportBlock
import com.eltavine.duckdetector.core.report.ReportFact
import com.eltavine.duckdetector.features.tee.presentation.model.TeeCardModel
import com.eltavine.duckdetector.features.tee.presentation.model.TeeFactRowModel

fun TeeCardModel.toDetectorReport(): DetectorReport = DetectorReport(
    title = title,
    verdict = verdict,
    severity = status.severity,
    quickFacts = headerFacts.map { ReportFact(it.label, it.value) },
    blocks = buildList {
        if (highlightSignals.isNotEmpty()) {
            add(ReportBlock.Verbatim("Highlight Signals", highlightSignals.map { "    • ${it.label}: ${it.value}" }))
        }
        factGroups.forEach { group ->
            add(ReportBlock.Verbatim(group.title, group.rows.flatMap(TeeFactRowModel::toReportLines)))
        }
        add(
            ReportBlock.Verbatim(
                title = "Environment & Network",
                lines = buildList {
                    add("    • Network Status    : ${networkState.summary}")
                    add("    • Certificate Count : ${certificateSummary.count}")
                    certificateSummary.certificates.forEachIndexed { index, certificate ->
                        add("    • Certificate ${index + 1}       : ${certificate.slotLabel}")
                        add("        Subject           : ${certificate.subject}")
                        add("        Issuer            : ${certificate.issuer}")
                        add("        Serial Number     : ${certificate.serialNumber}")
                        add("        Validity          : ${certificate.validFrom} to ${certificate.validUntil}")
                        add("        Signature          : ${certificate.signatureAlgorithm}")
                        add("        Public Key        : ${certificate.publicKeySummary}")
                    }
                },
            ),
        )
        if (exportText.isNotBlank()) {
            add(ReportBlock.Verbatim("TEE Detailed Export", exportText.trimEnd().lines().map { "    $it" }))
        }
    },
)

private fun TeeFactRowModel.toReportLines(): List<String> {
    val lines = value.trim().lines().map { it.trimEnd() }.filter { it.isNotBlank() }
    return if (lines.size <= 1) {
        listOf("    • $label: ${value.trim()}")
    } else {
        listOf("    • $label:") + lines.map { "        $it" }
    }
}
