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

import com.eltavine.duckdetector.capability.attestation.data.AttestedDeviceInfo
import com.eltavine.duckdetector.features.tee.data.native.NativeTeeSnapshot
import com.eltavine.duckdetector.features.tee.data.verification.certificate.DualAlgorithmChainResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.AesGcmRoundTripResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.IdAttestationResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.aesGcmFailureResult
import com.eltavine.duckdetector.features.tee.data.verification.strongbox.StrongBoxBehaviorResult
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.ProviderException
import javax.crypto.AEADBadTagException

class TeeReportReducerCryptoTest {

    private val reducer = TeeReportReducer()

    @Test
    fun `native syscall mismatch only stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                native = NativeTeeSnapshot(
                    syscallMismatchDetected = true,
                    trickyStoreMethods = listOf("SYSCALL_MISMATCH"),
                    trickyStoreDetails = "sys mismatch",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Indicators" && it.body == "0 policy hard • 0 policy review • 0 local"
        })
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Native" &&
                    it.body.contains("Syscall mismatch") &&
                    it.body.contains("vendor binder/libc", ignoreCase = true) &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `device ids omitted from attestation are not shown as unavailable`() {
        val report = reducer.reduce(
            baseArtifacts(
                deviceInfo = AttestedDeviceInfo(),
                idAttestation = IdAttestationResult(
                    mismatches = emptyList(),
                    unavailableFields = listOf(
                        "brand",
                        "device",
                        "product",
                        "manufacturer",
                        "model"
                    ),
                    detail = "Attestation did not expose any comparable device identifiers.",
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Attestation" }.items.any {
            it.title == "Device IDs" && it.body == "Not included in attestation"
        })
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "ID attestation" && it.body == "No comparable IDs exposed"
        })
    }

    @Test
    fun `graded oversized challenge lists accepted sizes`() {
        val report = reducer.reduce(
            baseArtifacts(
                oversizedChallenge = OversizedChallengeResult(
                    acceptedOversizedChallenge = true,
                    acceptedSizes = listOf(256, 512, 4096),
                    attemptedSizes = listOf(256, 512, 4096),
                    detail = "Attestation accepted oversized challenge sizes: 256B, 512B, 4096B.",
                ),
            ),
        )

        assertEquals(TeeVerdict.SUSPICIOUS, report.verdict)
        assertTrue(report.summary.contains("256B"))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Oversized challenge" && it.body.contains("256B") && it.body.contains("4096B")
        })
    }

    @Test
    fun `dual algorithm difference no longer drives verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                dualAlgorithm = DualAlgorithmChainResult(
                    mismatchDetected = true,
                    detail = "rsa/ec differ",
                    trustRootMismatch = true,
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Dual algorithm" &&
                    it.body.contains("difference observed") &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `strongbox keeps availability visible when an informational note is present`() {
        val report = reducer.reduce(
            baseArtifacts(
                strongBox = StrongBoxBehaviorResult(
                    requested = true,
                    advertised = true,
                    available = true,
                    keyInfoLevel = "StrongBox",
                    detail = "note",
                    warnings = listOf(
                        "StrongBox signing returned in 1900us, under the 2000us this probe expects of a discrete secure element.",
                        "StrongBox accepted RSA-4096, which is atypical for current hardware-backed implementations.",
                    ),
                ),
            ),
        )

        val item = report.sections.single { it.title == "Checks" }.items
            .single { it.title == "StrongBox" }
        assertTrue(item.body.contains("Available"))
        assertTrue(item.body.contains("StrongBox"))
        assertTrue(item.body.contains("1900us"))
        // Showing only the first note used to drop the rest.
        assertTrue(item.body.contains("RSA-4096"))
        assertEquals(TeeSignalLevel.INFO, item.level)
    }

    @Test
    fun `strongbox informational notes do not raise suspicion on their own`() {
        val onlyNotes = StrongBoxBehaviorResult(
            requested = true,
            advertised = true,
            available = true,
            detail = "note",
            warnings = listOf("StrongBox signing returned in 1900us, under the 2000us this probe expects of a discrete secure element."),
        )
        val hardFailure = StrongBoxBehaviorResult(
            requested = true,
            advertised = true,
            available = true,
            detail = "note",
            hardFailures = listOf("StrongBox key generation succeeded, but attestation tier came back as TEE."),
        )

        assertFalse(onlyNotes.suspicious)
        assertTrue(hardFailure.suspicious)
    }

    @Test
    fun `strongbox names why it could not confirm instead of only reporting not confirmed`() {
        val report = reducer.reduce(
            baseArtifacts(
                strongBox = StrongBoxBehaviorResult(
                    requested = true,
                    advertised = true,
                    available = false,
                    detail = "note",
                    keyInfoUnavailableDetail = "StrongBox reported itself unavailable during key generation.",
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "StrongBox" &&
                    it.body.contains("Not confirmed") &&
                    it.body.contains("reported itself unavailable")
        })
    }

    @Test
    fun `strongbox says only not confirmed when no reason was recorded`() {
        val report = reducer.reduce(
            baseArtifacts(
                strongBox = StrongBoxBehaviorResult(
                    requested = true,
                    advertised = true,
                    available = false,
                    detail = "note",
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "StrongBox" && it.body.contains("Not confirmed")
        })
    }

    @Test
    fun `strongbox heuristic warning stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                strongBox = StrongBoxBehaviorResult(
                    requested = true,
                    advertised = true,
                    available = true,
                    warnings = listOf("StrongBox accepted RSA-4096, which is atypical for current hardware-backed implementations."),
                    detail = "note",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "StrongBox" &&
                    it.body.contains("RSA-4096") &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `software backed aes gcm key becomes local review signal`() {
        val report = reducer.reduce(
            baseArtifacts(
                aesGcm = AesGcmRoundTripResult(
                    executed = true,
                    roundTripSucceeded = true,
                    keyInfoLevel = "Software",
                    insideSecureHardware = false,
                    detail = "software",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("software-backed", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "AES-GCM" &&
                    it.body.contains("software-backed", ignoreCase = true) &&
                    it.level == TeeSignalLevel.WARN
        })
    }

    @Test
    fun `aes gcm roundtrip failure becomes supplementary fail signal`() {
        val report = reducer.reduce(
            baseArtifacts(
                aesGcm = AesGcmRoundTripResult(
                    executed = true,
                    roundTripSucceeded = false,
                    keyInfoLevel = "TEE",
                    insideSecureHardware = true,
                    detail = "failed",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("AES-GCM", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "AES-GCM" &&
                    it.body.contains("Round-trip failed") &&
                    it.level == TeeSignalLevel.FAIL
        })
    }

    @Test
    fun `aes gcm probe that threw before a result stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(aesGcm = aesGcmFailureResult(ProviderException("Keystore backend busy"))),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "AES-GCM" &&
                    it.body == "Did not complete • Keystore backend busy" &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `aes gcm tag failure on its own ciphertext stays a fail`() {
        val result = aesGcmFailureResult(AEADBadTagException("mac check failed"))

        assertTrue(result.executed)
        assertFalse(result.roundTripSucceeded)
        val report = reducer.reduce(baseArtifacts(aesGcm = result))
        assertEquals(1, report.supplementaryIndicatorCount)
    }

    @Test
    fun `aes gcm round trip without authorization checks is not a pass`() {
        val report = reducer.reduce(
            baseArtifacts(
                aesGcm = AesGcmRoundTripResult(
                    executed = true,
                    roundTripSucceeded = true,
                    authorizationChecked = false,
                    keyInfoLevel = "TEE",
                    insideSecureHardware = true,
                    detail = "auth=not run",
                ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "AES-GCM" &&
                    it.body.endsWith("authorization checks did not run") &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `skipped aes gcm probe remains informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                aesGcm = AesGcmRoundTripResult(
                    executed = false,
                    detail = "AES-GCM round-trip probe skipped.",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "AES-GCM" &&
                    it.body == "Skipped" &&
                    it.level == TeeSignalLevel.INFO
        })
    }
}
