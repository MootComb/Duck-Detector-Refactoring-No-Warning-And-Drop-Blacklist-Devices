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

package com.eltavine.duckdetector.features.lsposed.presentation.model

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.report.DetectorHeadline

data class LSPosedCardModel(
    override val title: String,
    val subtitle: String,
    override val status: DetectorStatus,
    override val verdict: String,
    override val summary: String,
    val headerFacts: List<LSPosedHeaderFactModel>,
    val runtimeRows: List<LSPosedDetailRowModel>,
    val binderRows: List<LSPosedDetailRowModel>,
    val packageRows: List<LSPosedDetailRowModel>,
    val policyRows: List<LSPosedDetailRowModel>,
    val nativeRows: List<LSPosedDetailRowModel>,
    val impactItems: List<LSPosedImpactItemModel>,
    val methodRows: List<LSPosedDetailRowModel>,
    val scanRows: List<LSPosedDetailRowModel>,
) : DetectorHeadline

/** The facts in the card's header, in the order the export lists them. */
enum class LSPosedHeaderFact(val label: String) {
    CRITICAL("Critical"),
    REVIEW("Review"),
    BRIDGE("Bridge"),
    PACKAGES("Packages"),
}

data class LSPosedHeaderFactModel(
    val fact: LSPosedHeaderFact,
    val value: String,
    val status: DetectorStatus,
) {
    val label: String get() = fact.label
}

/** A row icon that names what the row is about; rows without one show their status icon. */
enum class LSPosedRowIcon {
    BRIDGE,
    PACKAGE,
    MEMORY,
    POLICY,
    HOOK,
}

data class LSPosedDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
    val icon: LSPosedRowIcon? = null,
)

data class LSPosedImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
