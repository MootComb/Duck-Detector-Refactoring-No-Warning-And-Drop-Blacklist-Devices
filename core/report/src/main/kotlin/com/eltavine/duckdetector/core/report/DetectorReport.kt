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

package com.eltavine.duckdetector.core.report

import com.eltavine.duckdetector.core.evidence.DetectionSeverity

public data class ReportFact(
    val label: String,
    val value: String,
)

public data class ReportRow(
    val label: String,
    val value: String,
    val detail: String? = null,
)

/** One titled section of a detector's exported report. */
public sealed interface ReportBlock {
    public val title: String

    /** Label/value rows with optional detail; omitted when there are no rows. */
    public data class Rows(
        override val title: String,
        val rows: List<ReportRow>,
    ) : ReportBlock

    /** Free-text items; continuation lines of an item stay indented under it; omitted when empty. */
    public data class Bullets(
        override val title: String,
        val items: List<String>,
    ) : ReportBlock

    /** Lines a detector lays out itself; always emitted, so the detector decides whether to include it. */
    public data class Verbatim(
        override val title: String,
        val lines: List<String>,
    ) : ReportBlock
}

/**
 * The export projection of one detector.
 *
 * Each detector builds its own from typed card data, so the exporter never inspects a
 * detector's models and changing one detector's report cannot affect another's.
 */
public data class DetectorReport(
    val title: String,
    val verdict: String,
    val severity: DetectionSeverity,
    val quickFacts: List<ReportFact>,
    val blocks: List<ReportBlock>,
)

/** Identity of the inspected device as shown in the report banner. */
public data class ReportDeviceIdentity(
    val brand: String?,
    val model: String?,
    val androidRelease: String?,
    val sdk: String?,
)

/** The device specification appendix that closes an exported report. */
public data class DeviceReport(
    val identity: ReportDeviceIdentity,
    val quickFacts: List<ReportFact>,
    val sections: List<ReportBlock.Verbatim>,
)
