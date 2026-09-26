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

package com.eltavine.duckdetector.features.selinux.data.probes

import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxContextValidityBridge
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxContextValiditySnapshot
import com.eltavine.duckdetector.features.selinux.data.repository.buildContextValidityMethod
import com.eltavine.duckdetector.features.selinux.domain.AppZygoteCarrierSupportState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxContextValidityReading
import com.eltavine.duckdetector.features.selinux.domain.SelinuxContextValidityVerdict
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import com.eltavine.duckdetector.features.selinux.domain.contextValiditySupportState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxContextValidityMethodTest {

    @Test
    fun `a clean reading is typed and keeps its text`() {
        val method = methodFor(trustedSnapshot())

        assertEquals(SelinuxOracle.CONTEXT_VALIDITY, method.oracle)
        assertEquals(SelinuxOracle.CONTEXT_VALIDITY.label, method.method)
        assertEquals(
            SelinuxContextValidityReading(SelinuxContextValidityVerdict.CLEAN, AppZygoteCarrierSupportState.AVAILABLE),
            method.contextValidity,
        )
        assertEquals(SelinuxContextValidityVerdict.CLEAN.label, method.status)
    }

    @Test
    fun `an untrusted reading flags repeatability exactly where its detail says so`() {
        val method = methodFor(trustedSnapshot().copy(ksuResultsStable = false))

        assertEquals(SelinuxContextValidityVerdict.SELF_TEST_FAILED, method.contextValidity?.verdict)
        assertEquals(true, method.contextValidity?.repeatabilityFailed)
        assertTrue(method.details.orEmpty().contains("repeatability failed"))
    }

    @Test
    fun `an unsupported reading carries the carrier state its detail names`() {
        val untrusted = methodFor(trustedSnapshot().copy(carrierMatchesExpected = false))
        val failed = methodFor(trustedSnapshot().copy(available = false))

        assertEquals(AppZygoteCarrierSupportState.UNTRUSTED, contextValiditySupportState(untrusted))
        assertTrue(untrusted.details.orEmpty().contains("Carrier state=untrusted"))
        assertEquals(AppZygoteCarrierSupportState.FAILED, contextValiditySupportState(failed))
        assertTrue(failed.details.orEmpty().contains("Carrier state=failed"))
    }

    private fun methodFor(snapshot: SelinuxContextValiditySnapshot) =
        buildContextValidityMethod(SelinuxContextValidityProbe(nativeBridge = FakeBridge(snapshot)).inspectLocal())

    private fun trustedSnapshot() = SelinuxContextValiditySnapshot(
        available = true,
        probeAttempted = true,
        carrierContext = "u:r:app_zygote:s0:c1,c2",
        carrierMatchesExpected = true,
        oracleControlsPassed = true,
        ksuResultsStable = true,
        ksuDomainValid = false,
        ksuFileValid = false,
    )

    private class FakeBridge(
        private val snapshot: SelinuxContextValiditySnapshot,
    ) : SelinuxContextValidityBridge() {
        override fun collectLocalSnapshot(): SelinuxContextValiditySnapshot = snapshot
    }
}
