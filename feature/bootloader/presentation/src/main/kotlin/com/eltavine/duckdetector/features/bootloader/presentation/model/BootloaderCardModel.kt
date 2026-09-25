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

package com.eltavine.duckdetector.features.bootloader.presentation.model

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.report.DetectorHeadline

enum class BootloaderCardAssessment {
    AUTHORITATIVE,
    CONSISTENCY_REVIEW,
    CONSISTENCY_CONFLICT,
}

data class BootloaderCardModel(
    override val title: String,
    val subtitle: String,
    override val status: DetectorStatus,
    val assessment: BootloaderCardAssessment,
    override val verdict: String,
    override val summary: String,
    val headerFacts: List<BootloaderHeaderFactModel>,
    val stateRows: List<BootloaderDetailRowModel>,
    val attestationRows: List<BootloaderDetailRowModel>,
    val propertyRows: List<BootloaderDetailRowModel>,
    val consistencyRows: List<BootloaderDetailRowModel>,
    val impactItems: List<BootloaderImpactItemModel>,
    val methodRows: List<BootloaderDetailRowModel>,
    val scanRows: List<BootloaderDetailRowModel>,
) : DetectorHeadline {
    val showConsistencyQuestionIcon: Boolean
        get() = assessment != BootloaderCardAssessment.AUTHORITATIVE

    val assessmentStatus: DetectorStatus?
        get() = when (assessment) {
            BootloaderCardAssessment.AUTHORITATIVE -> null
            BootloaderCardAssessment.CONSISTENCY_REVIEW -> DetectorStatus.warning()
            BootloaderCardAssessment.CONSISTENCY_CONFLICT -> DetectorStatus.danger()
        }
}

/** The facts in the card's header, in the order the export lists them. */
enum class BootloaderHeaderFact(val label: String) {
    STATE("State"),
    PROOF("Proof"),
    TIER("Tier"),
    TRUST("Trust"),
}

data class BootloaderHeaderFactModel(
    val fact: BootloaderHeaderFact,
    val value: String,
    val status: DetectorStatus,
) {
    val label: String get() = fact.label
}

data class BootloaderDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class BootloaderImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
