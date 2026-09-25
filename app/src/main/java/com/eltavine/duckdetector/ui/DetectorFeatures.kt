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

package com.eltavine.duckdetector.ui

import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.ui.detector.DetectorFeature
import com.eltavine.duckdetector.core.ui.detector.DeviceProfileFeature
import com.eltavine.duckdetector.features.deviceinfo.data.repository.DeviceInfoRepository
import com.eltavine.duckdetector.features.deviceinfo.ui.DeviceInfoProfileFeature
import com.eltavine.duckdetector.sdk.DetectorCatalog
import com.eltavine.duckdetector.ui.shell.DetectorConsentCard

/**
 * The dashboard card of every detector, and the device profile shown under them.
 *
 * Which detectors exist and the order their scans start come from [DetectorCatalog]. Each card comes
 * from its detector's ui layer through the generated [detectorCards], so this file names no detector;
 * everything central works on the sessions the cards create.
 */
internal object DetectorFeatures {
    private val cards: Map<DetectorId, DetectorFeature> = detectorCards.associateBy { it.id }

    /** Every detector's card, in the catalog's scan-start order. */
    val all: List<DetectorFeature> = DetectorCatalog.all.map { detector ->
        checkNotNull(cards[detector.id]) { "${detector.id} is in DetectorCatalog but has no card here" }
    }

    /** Every detector's consent cards, in catalog order. */
    val consentCards: List<DetectorConsentCard> = all.flatMap { feature ->
        feature.consentCards.map { card -> DetectorConsentCard(feature.id, card) }
    }

    val deviceProfile: DeviceProfileFeature = DeviceInfoProfileFeature { context -> DeviceInfoRepository(context) }

    init {
        val uncatalogued = cards.keys - DetectorCatalog.all.map { it.id }.toSet()
        check(uncatalogued.isEmpty()) { "cards for detectors missing from DetectorCatalog: $uncatalogued" }
        DetectorCatalog.all.zip(all).forEach { (detector, feature) ->
            check(feature.consentCards.map { it.consent } == detector.consents) {
                "${detector.id}'s consent cards do not match the consents it declares"
            }
        }
    }
}
