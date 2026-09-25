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
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test

class DetectorConsentsTest {

    private val network = ConsentId("network")
    private val storage = ConsentId("storage")

    @Test
    fun `no consents load at once`() = runBlocking {
        assertEquals(emptyMap<ConsentId, ConsentDecision>(), combineConsentDecisions(emptyMap()).first())
    }

    @Test
    fun `decisions are keyed by consent id and follow each change`() = runBlocking {
        val networkDecision = MutableStateFlow(ConsentDecision.UNDECIDED)
        val decisions = combineConsentDecisions(
            mapOf(network to networkDecision, storage to flowOf(ConsentDecision.DECLINED)),
        )

        assertEquals(
            mapOf(network to ConsentDecision.UNDECIDED, storage to ConsentDecision.DECLINED),
            decisions.first(),
        )
        networkDecision.value = ConsentDecision.GRANTED
        assertEquals(
            mapOf(network to ConsentDecision.GRANTED, storage to ConsentDecision.DECLINED),
            decisions.first(),
        )
    }

    @Test
    fun `nothing is emitted until every consent has loaded`() = runBlocking {
        val decisions = combineConsentDecisions(
            mapOf(network to flowOf(ConsentDecision.GRANTED), storage to emptyFlow()),
        )

        assertEquals(emptyList<Map<ConsentId, ConsentDecision>>(), decisions.toList())
    }
}
