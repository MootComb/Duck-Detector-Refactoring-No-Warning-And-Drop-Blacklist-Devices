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

package com.eltavine.duckdetector.features.zygisk.presentation

import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.core.report.ReportBlock
import com.eltavine.duckdetector.core.report.ReportFact
import com.eltavine.duckdetector.core.report.ReportRow
import com.eltavine.duckdetector.features.zygisk.presentation.model.ZygiskCardModel
import com.eltavine.duckdetector.features.zygisk.presentation.model.ZygiskDetailRowModel

fun ZygiskCardModel.toDetectorReport(): DetectorReport = DetectorReport(
    title = title,
    verdict = verdict,
    severity = status.severity,
    quickFacts = headerFacts.map { ReportFact(it.label, it.value) },
    blocks = buildList {
        add(ReportBlock.Rows("State", stateRows.toReportRows()))
        add(ReportBlock.Rows("Signals", signalRows.toReportRows()))
        add(ReportBlock.Rows("Methods", methodRows.toReportRows()))
        add(ReportBlock.Bullets("Impact & Guidance", impactItems.map { it.text }))
        if (references.isNotEmpty()) {
            add(ReportBlock.Verbatim("References", references.map { "    • $it" }))
        }
    },
)

private fun List<ZygiskDetailRowModel>.toReportRows(): List<ReportRow> =
    map { ReportRow(it.label, it.value, it.detail) }
