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

package com.eltavine.duckdetector.features.su.presentation.model

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.report.DetectorHeadline

data class SuCardModel(
    override val title: String,
    val subtitle: String,
    override val status: DetectorStatus,
    override val verdict: String,
    override val summary: String,
    val headerFacts: List<SuHeaderFactModel>,
    val artifactRows: List<SuDetailRowModel>,
    val contextRows: List<SuDetailRowModel>,
    val impactItems: List<SuImpactItemModel>,
    val methodRows: List<SuDetailRowModel>,
    val scanRows: List<SuDetailRowModel>,
) : DetectorHeadline

/** The facts in the card's header, in the order the export lists them. */
enum class SuHeaderFact(val label: String) {
    ARTIFACTS("Artifacts"),
    DAEMONS("Daemons"),
    CONTEXT("Context"),
    PROCESSES("Processes"),
}

data class SuHeaderFactModel(
    val fact: SuHeaderFact,
    val value: String,
    val status: DetectorStatus,
) {
    val label: String get() = fact.label
}

data class SuDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class SuImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
