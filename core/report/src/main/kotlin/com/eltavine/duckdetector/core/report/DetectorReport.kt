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

import com.eltavine.duckdetector.core.evidence.ContractValue
import com.eltavine.duckdetector.core.evidence.DetectionSeverity

@ContractValue
public class ReportFact(
    public val label: String,
    public val value: String,
)

@ContractValue
public class ReportRow(
    public val label: String,
    public val value: String,
    public val detail: String? = null,
)

/** One titled section of a detector's exported report. */
public sealed interface ReportBlock {
    public val title: String

    /** Label/value rows with optional detail; omitted when there are no rows. */
    @ContractValue
    public class Rows(
        override val title: String,
        public val rows: List<ReportRow>,
    ) : ReportBlock

    /** Free-text items; continuation lines of an item stay indented under it; omitted when empty. */
    @ContractValue
    public class Bullets(
        override val title: String,
        public val items: List<String>,
    ) : ReportBlock

    /** Lines a detector lays out itself; always emitted, so the detector decides whether to include it. */
    @ContractValue
    public class Verbatim(
        override val title: String,
        public val lines: List<String>,
    ) : ReportBlock
}

/**
 * The export projection of one detector.
 *
 * Each detector builds its own from typed card data, so the exporter never inspects a
 * detector's models and changing one detector's report cannot affect another's.
 */
@ContractValue
public class DetectorReport(
    public val title: String,
    public val verdict: String,
    public val severity: DetectionSeverity,
    public val quickFacts: List<ReportFact>,
    public val blocks: List<ReportBlock>,
)

/** Identity of the inspected device as shown in the report banner. */
@ContractValue
public class ReportDeviceIdentity(
    public val brand: String?,
    public val model: String?,
    public val androidRelease: String?,
    public val sdk: String?,
)

/** The device specification appendix that closes an exported report. */
@ContractValue
public class DeviceReport(
    public val identity: ReportDeviceIdentity,
    public val quickFacts: List<ReportFact>,
    public val sections: List<ReportBlock.Verbatim>,
)
