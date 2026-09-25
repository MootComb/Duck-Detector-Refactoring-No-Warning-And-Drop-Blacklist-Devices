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

package com.eltavine.duckdetector.features.deviceinfo.presentation

import com.eltavine.duckdetector.core.report.DeviceReport
import com.eltavine.duckdetector.core.report.ReportBlock
import com.eltavine.duckdetector.core.report.ReportDeviceIdentity
import com.eltavine.duckdetector.core.report.ReportFact
import com.eltavine.duckdetector.features.deviceinfo.ui.model.DeviceInfoCardModel

fun DeviceInfoCardModel.toDeviceReport(): DeviceReport = DeviceReport(
    identity = ReportDeviceIdentity(
        brand = headerFactValue("brand"),
        model = headerFactValue("model"),
        androidRelease = headerFactValue("android"),
        sdk = headerFactValue("sdk"),
    ),
    quickFacts = headerFacts.map { ReportFact(it.label, it.value) },
    sections = sections.map { section ->
        val maxLabelLength = section.rows.maxOfOrNull { it.label.length } ?: 16
        val labelWidth = (maxLabelLength + 2).coerceIn(16, 28)
        ReportBlock.Verbatim(
            title = section.title,
            lines = section.rows.map { row -> "    • ${row.label.padEnd(labelWidth)}: ${row.value}" },
        )
    },
)

// The header facts are labelled by DeviceInfoCardModelMapper in this feature; the lookup stays here
// so no other module has to know those labels.
private fun DeviceInfoCardModel.headerFactValue(label: String): String? =
    headerFacts.firstOrNull { it.label.equals(label, ignoreCase = true) }?.value
