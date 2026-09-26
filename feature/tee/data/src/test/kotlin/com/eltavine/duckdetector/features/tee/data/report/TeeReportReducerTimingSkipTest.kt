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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TeeReportReducerTimingSkipTest {

    private val reducer = TeeReportReducer()

    @Test
    fun `timing side-channel skipped getKeyEntry stack marks tricky-store patch mode as fail`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = false,
                    sampleCount = 0,
                    warmupCount = 5,
                    timerSource = "arm64_cntvct",
                    affinity = "bound_cpu0",
                    failureReason = "cleanup failed",
                    stackCopyPayload = """
                        phase=warmup.attested[0]
                        summary=ServiceSpecificException(code 7)

                        Caused by: android.os.ServiceSpecificException (code 7)
                        	at android.os.Parcel.createException(Parcel.java:3353)
                        	at android.os.Parcel.readException(Parcel.java:3336)
                        	at ${'$'}Proxy5.getKeyEntry(Unknown Source)
                    """.trimIndent(),
                    detail = "measurement unavailable after getKeyEntry failure",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("matched a known keystore-interception module", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Matched a known keystore-interception module") &&
                    it.body.contains("Register timer") &&
                    it.body.contains("bound_cpu0") &&
                    it.level == TeeSignalLevel.FAIL
        })
        assertFalse(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" && it.body.contains("Measurement unavailable")
        })
    }

    @Test
    fun `timing side-channel skipped generateKey and deleteKey stack marks tee simulator patch mode as fail`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = false,
                    sampleCount = 0,
                    warmupCount = 5,
                    timerSource = "clock_monotonic",
                    affinity = "not_requested",
                    failureReason = "security level generateKey failed",
                    stackCopyPayload = """
                        phase=securityLevel.generateKey
                        summary=ServiceSpecificException(code -49)

                        android.os.ServiceSpecificException (code -49)
                        	at android.os.Parcel.createExceptionOrNull(Parcel.java:3383)
                        	at android.os.Parcel.createException(Parcel.java:3353)
                        	at android.os.Parcel.readException(Parcel.java:3336)
                        	at ${'$'}Proxy7.generateKey(Unknown Source)

                        Caused by:
                            0: Legacy database is empty.
                            1: Error::Rc(r#KEY_NOT_FOUND) (code 7)
                        	at ${'$'}Proxy5.deleteKey(Unknown Source)
                    """.trimIndent(),
                    detail = "measurement unavailable after legacy database failure",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("matched a known keystore-interception module", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Matched a known keystore-interception module") &&
                    it.body.contains("Fallback timer") &&
                    it.body.contains("not_requested") &&
                    it.level == TeeSignalLevel.FAIL
        })
        assertFalse(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" && it.body.contains("Measurement unavailable")
        })
    }

    @Test
    fun `timing side-channel skipped legacy database code 75 stack marks tee simulator patch and generate mode as fail`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = false,
                    sampleCount = 0,
                    warmupCount = 5,
                    timerSource = "clock_monotonic",
                    affinity = "not_requested",
                    failureReason = "security level generateKey failed",
                    stackCopyPayload = """
                        phase=securityLevel.generateKey
                        summary=ServiceSpecificException(code -75)

                        android.os.ServiceSpecificException (code -75)
                        	at android.os.Parcel.createExceptionOrNull(Parcel.java:3270)
                        	at android.os.Parcel.createException(Parcel.java:3240)
                        	at android.os.Parcel.readException(Parcel.java:3223)

                        Caused by:
                            0: Legacy database is empty.
                            1: Error::Rc(r#KEY_NOT_FOUND) (code 7)
                    """.trimIndent(),
                    detail = "measurement unavailable after legacy database failure",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(2, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("matched a known keystore-interception module", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Matched a known keystore-interception module") &&
                    it.body.contains("Fallback timer") &&
                    it.body.contains("not_requested") &&
                    it.level == TeeSignalLevel.FAIL
        })
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "TEE Simulator generate-mode fingerprint" &&
                    it.body.contains("Matched TEE Simulator generate-mode fingerprint.") &&
                    it.level == TeeSignalLevel.FAIL &&
                    it.hiddenCopyText == null
        })
        assertFalse(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" && it.body.contains("Measurement unavailable")
        })
    }

    @Test
    fun `timing side-channel skipped parcel trio falls back to warning private binder exception`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = false,
                    sampleCount = 0,
                    warmupCount = 5,
                    timerSource = "clock_monotonic",
                    affinity = "not_requested",
                    failureReason = "security level probe failed",
                    appAttestKeyAdvertised = true,
                    stackCopyPayload = """
                        phase=securityLevel.generateKey
                        summary=ServiceSpecificException(code -1)

                        android.os.ServiceSpecificException (code -1)
                        	at android.os.Parcel.createExceptionOrNull(Parcel.java:3270)
                        	at android.os.Parcel.createException(Parcel.java:3240)
                        	at android.os.Parcel.readException(Parcel.java:3223)
                    """.trimIndent(),
                    detail = "measurement unavailable after generic parcel failure",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("private binder exception during timing skip", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" &&
                    it.body.contains("Captured private binder exception during timing skip") &&
                    it.body.contains("Fallback timer") &&
                    it.body.contains("not_requested") &&
                    it.level == TeeSignalLevel.WARN
        })
        assertFalse(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" && it.body.contains("Measurement unavailable")
        })
    }

    @Test
    fun `parcel trio is not a finding where app attestation keys are not advertised`() {
        val report = reducer.reduce(
            baseArtifacts(
                timingSideChannel = TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = false,
                    appAttestKeyAdvertised = false,
                    failureReason = "security level probe failed",
                    stackCopyPayload = """
                        phase=securityLevel.generateKey
                        summary=ServiceSpecificException(code -2)

                        android.os.ServiceSpecificException (code -2)
                        	at android.os.Parcel.createExceptionOrNull(Parcel.java:3270)
                        	at android.os.Parcel.createException(Parcel.java:3240)
                        	at android.os.Parcel.readException(Parcel.java:3223)
                    """.trimIndent(),
                    detail = "ATTEST_KEY refused",
                ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Timing side-channel" && it.level == TeeSignalLevel.INFO
        })
    }
}
