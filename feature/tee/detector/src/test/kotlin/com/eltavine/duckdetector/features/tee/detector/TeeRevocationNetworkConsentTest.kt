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

import com.eltavine.duckdetector.core.detector.ConsentDecision
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefs
import org.junit.Assert.assertEquals
import org.junit.Test

class TeeRevocationNetworkConsentTest {

    @Test
    fun `an unasked consent is undecided whatever the stored answer`() {
        assertEquals(ConsentDecision.UNDECIDED, prefs(asked = false, granted = false).consentDecision())
        assertEquals(ConsentDecision.UNDECIDED, prefs(asked = false, granted = true).consentDecision())
    }

    @Test
    fun `an asked consent follows the stored answer`() {
        assertEquals(ConsentDecision.GRANTED, prefs(asked = true, granted = true).consentDecision())
        assertEquals(ConsentDecision.DECLINED, prefs(asked = true, granted = false).consentDecision())
    }

    @Test
    fun `TEE declares the consent`() {
        assertEquals(listOf(TeeRevocationNetworkConsent), TeeDetector.consents)
    }

    private fun prefs(asked: Boolean, granted: Boolean) = TeeNetworkPrefs(
        consentAsked = asked,
        consentGranted = granted,
        crlCacheJson = null,
        crlFetchedAt = 0L,
    )
}
