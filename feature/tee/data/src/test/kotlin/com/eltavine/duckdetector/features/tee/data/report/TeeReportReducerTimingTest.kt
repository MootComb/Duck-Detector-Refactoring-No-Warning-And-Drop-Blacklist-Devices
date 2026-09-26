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

import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingSideChannelResult
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TeeReportReducerTimingTest {

    private val reducer = TeeReportReducer()

    @Test
    fun `timing side-channel positive result becomes supplementary review and exposes metrics`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = true,
                    suspicious = true,
                    sampleCount = 18,
                    attemptedPairCount = 20,
                    successfulPairCount = 20,
                    failedPairCount = 0,
                    filteredOutlierCount = 2,
                    ratioEligible = true,
                    warmupCount = 5,
                    avgAttestedMillis = 0.612,
                    avgNonAttestedMillis = 0.400,
                    diffMillis = 0.212,
                    detail = "register timer source; avgAttested=0.612ms, avgNonAttested=0.400ms, diff=0.212ms",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("timing side-channel", ignoreCase = true))
        assertTrue(report.summary.contains("supplementary", ignoreCase = true))
        assertTrue(report.summary.contains("ratio 1.53x exceeded 1.1x", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Register timer") &&
                    it.body.contains("attested 0.612ms") &&
                    it.body.contains("non-attested 0.400ms") &&
                    it.body.contains("diff 0.212ms") &&
                    it.body.contains("failedPairs=0/20") &&
                    it.body.contains("outlierFiltered=2/20") &&
                    it.body.contains("samples=18") &&
                    it.body.contains("ratio 1.530x") &&
                    it.body.contains("threshold > 1.1x") &&
                    it.level == TeeSignalLevel.WARN
        })
    }

    @Test
    fun `timing side-channel insufficient samples skip ratio without supplementary review`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = true,
                    suspicious = true,
                    sampleCount = 299,
                    attemptedPairCount = 500,
                    successfulPairCount = 320,
                    failedPairCount = 180,
                    filteredOutlierCount = 21,
                    ratioEligible = false,
                    ratioSkipReason = "insufficientSamples=299/300",
                    warmupCount = 5,
                    avgAttestedMillis = 0.612,
                    avgNonAttestedMillis = 0.400,
                    diffMillis = 0.212,
                    detail = "register timer source; insufficientSamples=299/300",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("ratio skipped") &&
                    it.body.contains("failedPairs=180/500") &&
                    it.body.contains("outlierFiltered=21/320") &&
                    it.body.contains("samples=299") &&
                    it.body.contains("insufficientSamples=299/300") &&
                    it.body.contains("Ratio skipped") &&
                    !it.body.contains("Positive") &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `timing side-channel invalid ratio stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = true,
                    suspicious = false,
                    sampleCount = 20,
                    warmupCount = 5,
                    avgAttestedMillis = 0.200,
                    avgNonAttestedMillis = 0.000,
                    diffMillis = 0.200,
                    detail = "fallback timer path; avgAttested=0.200ms, avgNonAttested=0.000ms, diff=0.200ms",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Fallback timer") &&
                    it.body.contains("diff 0.200ms") &&
                    it.body.contains("ratio n/a") &&
                    it.body.contains("Not positive") &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `timing side-channel negative threshold breach becomes supplementary review with fallback wording`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = true,
                    suspicious = true,
                    sampleCount = 20,
                    warmupCount = 5,
                    avgAttestedMillis = 0.100,
                    avgNonAttestedMillis = 0.450,
                    diffMillis = -0.350,
                    detail = "fallback timer path; avgAttested=0.100ms, avgNonAttested=0.450ms, diff=-0.350ms",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("Fallback timer timing side-channel stayed supplementary"))
        assertTrue(report.summary.contains("ratio 4.50x exceeded 1.1x"))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Fallback timer") &&
                    it.body.contains("diff -0.350ms") &&
                    it.body.contains("ratio 4.500x") &&
                    it.body.contains("threshold > 1.1x") &&
                    it.level == TeeSignalLevel.WARN
        })
    }

    @Test
    fun `timing side-channel degraded result still shows timer affinity and reason`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = false,
                    suspicious = false,
                    sampleCount = 500,
                    warmupCount = 5,
                    source = "keystore2_getKeyEntry_binder",
                    timerSource = "arm64_cntvct",
                    affinity = "bound_cpu0",
                    failureReason = "Keystore2 getKeyEntry transact returned false",
                    stackCopyPayload = "phase=warmup.attested[0]\nsummary=ServiceSpecificException(code 7)",
                    detail = "measurement unavailable after binder transact failure",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Register timer") &&
                    it.body.contains("bound_cpu0") &&
                    it.body.contains("Measurement unavailable") &&
                    it.body.contains("reason Keystore2 getKeyEntry transact returned false") &&
                    it.level == TeeSignalLevel.INFO
        })
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                it.hiddenCopyText?.contains("phase=warmup.attested[0]") == true
        })
    }

    @Test
    fun `timing side-channel negative measured result still shows timer and affinity`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = true,
                    suspicious = false,
                    sampleCount = 1000,
                    warmupCount = 5,
                    avgAttestedMillis = 0.280,
                    avgNonAttestedMillis = 0.120,
                    diffMillis = 0.160,
                    source = "keystore2_getKeyEntry_binder",
                    timerSource = "arm64_cntvct",
                    affinity = "bound_cpu0",
                    detail = "stable negative measurement",
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Register timer") &&
                    it.body.contains("bound_cpu0") &&
                    it.body.contains("attested 0.280ms") &&
                    it.body.contains("non-attested 0.120ms") &&
                    it.body.contains("diff 0.160ms") &&
                    it.body.contains("Not positive") &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `timing side-channel partial samples still show available timing context`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = true,
                    suspicious = false,
                    sampleCount = 1000,
                    warmupCount = 5,
                    avgAttestedMillis = 0.310,
                    avgNonAttestedMillis = null,
                    diffMillis = null,
                    source = "keystore2_getKeyEntry_binder",
                    timerSource = "arm64_cntvct",
                    affinity = "bound_cpu0",
                    failureReason = "non-attested path unavailable",
                    detail = "partial timing measurement",
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Register timer") &&
                    it.body.contains("bound_cpu0") &&
                    it.body.contains("attested 0.310ms") &&
                    it.body.contains("non-attested n/a") &&
                    it.body.contains("diff n/a") &&
                    it.body.contains("Not positive") &&
                    it.body.contains("reason non-attested path unavailable") &&
                    it.level == TeeSignalLevel.INFO
        })
    }
}
