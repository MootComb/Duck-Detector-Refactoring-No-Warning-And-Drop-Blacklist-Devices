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

package com.eltavine.duckdetector.ui.shell

import com.eltavine.duckdetector.core.detector.ConsentDecision
import com.eltavine.duckdetector.core.detector.ConsentId
import com.eltavine.duckdetector.core.detector.DetectorConsent
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.ui.detector.ConsentCard
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map

/** A consent card with the detector whose scans its decision affects. */
internal class DetectorConsentCard(
    val detectorId: DetectorId,
    val card: ConsentCard,
) {
    val consent: DetectorConsent get() = card.consent
}

/**
 * Every consent's decision by consent id. It emits once every consent's decision has loaded, which
 * the startup gate waits for, and again whenever one of them changes.
 */
internal fun combineConsentDecisions(
    decisions: Map<ConsentId, Flow<ConsentDecision>>,
): Flow<Map<ConsentId, ConsentDecision>> {
    if (decisions.isEmpty()) return flowOf(emptyMap())
    val entries = decisions.map { (id, decision) -> decision.map { id to it } }
    return combine(entries) { loaded -> loaded.toMap() }
}
