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

package com.eltavine.duckdetector.features.zygisk.presentation.model

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.report.DetectorHeadline

data class ZygiskCardModel(
    override val title: String,
    val subtitle: String,
    override val status: DetectorStatus,
    override val verdict: String,
    override val summary: String,
    val headerFacts: List<ZygiskHeaderFactModel>,
    val stateRows: List<ZygiskDetailRowModel>,
    val impactItems: List<ZygiskImpactItemModel>,
    val methodRows: List<ZygiskDetailRowModel>,
    val signalRows: List<ZygiskDetailRowModel>,
    val references: List<String>,
) : DetectorHeadline

/** The facts in the card's header, in the order the export lists them. */
enum class ZygiskHeaderFact(val label: String) {
    STATE("State"),
    CONFIDENCE("Confidence"),
    FD_TRAP("FD trap"),
    NATIVE("Native"),
}

data class ZygiskHeaderFactModel(
    val fact: ZygiskHeaderFact,
    val value: String,
    val status: DetectorStatus,
) {
    val label: String get() = fact.label
}

data class ZygiskDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class ZygiskImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
