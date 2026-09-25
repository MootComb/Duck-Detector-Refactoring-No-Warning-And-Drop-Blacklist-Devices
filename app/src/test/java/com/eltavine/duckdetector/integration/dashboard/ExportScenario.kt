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

package com.eltavine.duckdetector.integration.dashboard

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.core.scan.DetectorSummary
import com.eltavine.duckdetector.features.dashboard.presentation.export.DashboardExport
import com.eltavine.duckdetector.features.dashboard.presentation.export.ExportHeader
import com.eltavine.duckdetector.features.dashboard.presentation.model.buildDashboardFindings
import com.eltavine.duckdetector.features.dashboard.presentation.model.buildDashboardOverview
import com.eltavine.duckdetector.features.deviceinfo.presentation.model.DeviceInfoCardModel
import com.eltavine.duckdetector.features.deviceinfo.presentation.model.DeviceInfoHeaderFactModel
import com.eltavine.duckdetector.features.deviceinfo.presentation.toDeviceReport
import com.eltavine.duckdetector.sdk.DetectorCatalog

/** One fully populated dashboard export built from generated card models. */
internal class ExportScenario(seed: Int, withScanTime: Boolean = false, minListSize: Int = 0) {

    private val fixtures = CardFixtures(seed, minListSize)
    // Every card model is drawn from the one seeded sequence, so the golden export depends on this order.
    private val reports: List<DetectorReport> = DetectorCatalog.all
        .sortedBy { it.id.value }
        .map(fixtures::export)
    private val device = fixtures.create(DeviceInfoCardModel::class.java).let { generated ->
        val identity = when (seed % 3) {
            1 -> listOf(fact("Brand", "Duck"), fact("Model", "Pond 7"), fact("Android", "17"), fact("SDK", "37"))
            2 -> listOf(fact("brand", "Duck"), fact("MODEL", "Pond 7"), fact("Android", "17"))
            else -> emptyList()
        }
        generated.copy(headerFacts = identity + generated.headerFacts)
    }
    private val summaries = reports.mapIndexed { index, report ->
        DetectorSummary(
            id = DetectorId("detector_$index"),
            title = report.title,
            status = DetectorStatus(report.severity, if (report.severity == DetectionSeverity.INFO) InfoKind.ERROR else null),
            headline = report.verdict,
            summary = "Summary for ${report.title}",
            ready = index % 5 != 4,
        )
    }
    private val overview = buildDashboardOverview(
        contributions = summaries,
        scanDurationMillis = if (withScanTime) 1_234L else null,
        scanCompletedAtEpochMillis = if (withScanTime) 1_700_000_000_000L else null,
    )
    private val findings = buildDashboardFindings(summaries)

    fun export(header: ExportHeader): DashboardExport = DashboardExport(
        header = header,
        overview = overview,
        topFindings = findings,
        detectors = reports,
        device = device.toDeviceReport(),
    )

    private fun fact(label: String, value: String) = DeviceInfoHeaderFactModel(label, value)
}
