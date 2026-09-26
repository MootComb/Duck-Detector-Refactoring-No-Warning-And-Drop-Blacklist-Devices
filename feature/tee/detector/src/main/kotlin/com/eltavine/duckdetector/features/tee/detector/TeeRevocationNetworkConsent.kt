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

package com.eltavine.duckdetector.features.tee.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.ConsentDecision
import com.eltavine.duckdetector.core.detector.ConsentId
import com.eltavine.duckdetector.core.detector.DetectorConsent
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkConsentStore
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefs
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map

/**
 * Whether TEE's revocation check may fetch Google's attestation revocation feed. Undecided or
 * declined, the check uses only the built-in snapshot, and the TEE report says which of the two
 * applies. Every decision also drops the cached feed, as the store always has.
 */
public object TeeRevocationNetworkConsent : DetectorConsent {
    override val id: ConsentId = ConsentId("revocation_network")

    override fun decisions(context: Context): Flow<ConsentDecision> =
        TeeNetworkConsentStore.getInstance(context).prefs
            .map { prefs -> prefs.consentDecision() }
            .distinctUntilChanged()

    override suspend fun decide(context: Context, granted: Boolean) {
        TeeNetworkConsentStore.getInstance(context).setConsent(granted)
    }
}

/** The same order `CrlStatusService` reads the preferences in: first whether asked, then the answer. */
internal fun TeeNetworkPrefs.consentDecision(): ConsentDecision = when {
    !consentAsked -> ConsentDecision.UNDECIDED
    consentGranted -> ConsentDecision.GRANTED
    else -> ConsentDecision.DECLINED
}
