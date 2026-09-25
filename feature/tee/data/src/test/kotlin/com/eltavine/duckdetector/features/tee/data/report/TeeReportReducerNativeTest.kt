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

package com.eltavine.duckdetector.features.tee.data.report

import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.core.native.NativeCollectionOutcome
import com.eltavine.duckdetector.core.native.NativeCollectionStatus
import com.eltavine.duckdetector.features.tee.data.native.NativeTeeSnapshot
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict
import com.eltavine.duckdetector.features.tee.domain.toDetectorStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TeeReportReducerNativeTest {

    private val reducer = TeeReportReducer()

    @Test
    fun `aligned attestation with native probes that did not run is not all-clear`() {
        val report = reducer.reduce(
            baseArtifacts(
                tier = TeeTier.TEE,
                native = NativeTeeSnapshot(
                    collection = NativeCollectionStatus(
                        outcome = NativeCollectionOutcome.LIBRARY_UNAVAILABLE,
                        detail = "duckdetector could not be loaded: UnsatisfiedLinkError",
                    ),
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertFalse(report.nativeProbesAvailable)
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), report.toDetectorStatus())
        assertEquals("Attestation aligned; native probes did not run", report.headline)
        val native = report.sections.single { it.title == "Checks" }.items.single { it.title == "Native" }
        assertTrue(native.body, native.body.startsWith("Native process-side probes did not run"))
    }

    @Test
    fun `ioctl interception seen three ways is one finding apart from a maps hit`() {
        val artifacts = baseArtifacts(
            native = NativeTeeSnapshot(
                trickyStoreDetected = true,
                trickyStoreMapsHitDetected = true,
                gotHookDetected = true,
                inlineHookDetected = true,
                honeypotDetected = true,
                trickyStoreMethods = listOf("MAPS_NAME_HIT", "GOT_HOOK", "INLINE_HOOK", "HONEYPOT"),
                trickyStoreDetails = "hooked",
            ),
        )

        assertEquals(2, reducer.reduce(artifacts).supplementaryIndicatorCount)
        val indicators = collectSupplementaryIndicators(artifacts)
        val ioctl = indicators.single { it.title == "TrickyStore ioctl" }
        assertTrue(ioctl.body.contains("GOT") && ioctl.body.contains("prologue") && ioctl.body.contains("honeypot"))
        assertTrue(indicators.any { it.title == "TrickyStore" })
    }

    @Test
    fun `collected native probes keep aligned attestation all-clear`() {
        val report = reducer.reduce(baseArtifacts(tier = TeeTier.TEE))

        assertTrue(report.nativeProbesAvailable)
        assertEquals(DetectorStatus.allClear(), report.toDetectorStatus())
    }
}
