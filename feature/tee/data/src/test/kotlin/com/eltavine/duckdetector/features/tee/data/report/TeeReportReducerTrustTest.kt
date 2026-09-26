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

import com.eltavine.duckdetector.capability.attestation.data.CertificateTrustResult
import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import com.eltavine.duckdetector.capability.attestation.domain.TeeTrustRoot
import com.eltavine.duckdetector.features.tee.data.verification.crl.RevokedCertificate
import com.eltavine.duckdetector.features.tee.data.verification.crl.RevokedCertificateEvidenceKind
import com.eltavine.duckdetector.features.tee.data.verification.strongbox.StrongBoxBehaviorResult
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkMode
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkState
import com.eltavine.duckdetector.features.tee.domain.TeeRkpState
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeSoterState
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TeeReportReducerTrustTest {

    private val reducer = TeeReportReducer()

    @Test
    fun `unknown strongbox attestation tier no longer creates supplementary review`() {
        val report = reducer.reduce(
            baseArtifacts(
                tier = TeeTier.TEE,
                strongBox = StrongBoxBehaviorResult(
                    requested = true,
                    advertised = true,
                    available = true,
                    attestationTier = TeeTier.UNKNOWN,
                    keyInfoLevel = "StrongBox",
                    warnings = listOf(
                        "StrongBox key generation succeeded, but dedicated attestation did not expose a tier.",
                    ),
                    detail = "unknown tier",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(TeeTier.STRONGBOX, report.tier)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertEquals("Attestation, trust path, and revocation checks line up.", report.summary)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "StrongBox" &&
                    it.body.contains("did not expose a tier") &&
                    it.level == TeeSignalLevel.INFO
        })
    }

    @Test
    fun `confirmed strongbox upgrades displayed tier from tee`() {
        val report = reducer.reduce(
            baseArtifacts(
                tier = TeeTier.TEE,
                strongBox = StrongBoxBehaviorResult(
                    requested = true,
                    advertised = true,
                    available = true,
                    attestationTier = TeeTier.STRONGBOX,
                    keyInfoLevel = "StrongBox",
                    detail = "confirmed",
                ),
            ),
        )

        assertEquals(TeeTier.STRONGBOX, report.tier)
        assertTrue(report.sections.single { it.title == "Attestation" }.items.any {
            it.title == "Tier" &&
                    it.body.contains("StrongBox") &&
                    it.body.contains("attest TEE")
        })
    }

    @Test
    fun `software tier is not upgraded by strongbox side probe`() {
        val report = reducer.reduce(
            baseArtifacts(
                tier = TeeTier.SOFTWARE,
                strongBox = StrongBoxBehaviorResult(
                    requested = true,
                    advertised = true,
                    available = true,
                    attestationTier = TeeTier.STRONGBOX,
                    keyInfoLevel = "StrongBox",
                    detail = "confirmed",
                ),
            ),
        )

        assertEquals(TeeTier.SOFTWARE, report.tier)
        assertTrue(report.sections.single { it.title == "Attestation" }.items.any {
            it.title == "Tier" &&
                    it.body.startsWith("Software") &&
                    it.body.contains("sb attest StrongBox")
        })
    }

    @Test
    fun `disabled online crl refresh still reports built in snapshot`() {
        val report = reducer.reduce(
            baseArtifacts(
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.SKIPPED,
                    summary = "Built-in revocation snapshot is active; online refresh is disabled in Settings.",
                    cacheEntries = 1,
                    usedCache = true,
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Trust" }.items.any {
            it.title == "CRL" && it.body.contains("Built-in snapshot")
        })
        assertTrue(report.signals.any { it.label == "CRL" && it.value == "Built-in" })
    }

    @Test
    fun `local mass abuse revocation is warning not tampered`() {
        val report = reducer.reduce(
            baseArtifacts(
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.SKIPPED,
                    summary = "Built-in revocation snapshot is active; online refresh is disabled in Settings.",
                    cacheEntries = 1,
                    usedCache = true,
                ),
                crlRevokedCertificates = listOf(
                    RevokedCertificate(
                        serial = "8616ef30679ed43cc2b43e3c97a2319e / 178194732304493...",
                        reason = "MASS_ABUSE",
                        evidenceKind = RevokedCertificateEvidenceKind.LOCAL_MASS_ABUSE,
                    )
                ),
            ),
        )

        assertEquals(TeeVerdict.SUSPICIOUS, report.verdict)
        assertTrue(report.summary.contains("mass abuse", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Trust" }.items.any {
            it.title == "CRL" &&
                    it.body.contains("mass abuse", ignoreCase = true) &&
                    it.level == TeeSignalLevel.WARN
        })
        assertTrue(report.signals.any {
            it.label == "CRL" && it.value == "Mass abuse" && it.level == TeeSignalLevel.WARN
        })
    }

    @Test
    fun `standard crl revocation remains tampered`() {
        val report = reducer.reduce(
            baseArtifacts(
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.ACTIVE,
                    summary = "Online revocation data refreshed successfully.",
                ),
                crlRevokedCertificates = listOf(
                    RevokedCertificate(
                        serial = "8616ef30679ed43cc2b43e3c97a2319e / 178194732304493...",
                        reason = "KEY_COMPROMISE",
                    )
                ),
            ),
        )

        assertEquals(TeeVerdict.TAMPERED, report.verdict)
        assertTrue(report.sections.single { it.title == "Trust" }.items.any {
            it.title == "CRL" &&
                    it.body.contains("revoked", ignoreCase = true) &&
                    it.level == TeeSignalLevel.FAIL
        })
        assertTrue(report.signals.any {
            it.label == "CRL" && it.value == "Revoked" && it.level == TeeSignalLevel.FAIL
        })
    }

    @Test
    fun `refresh failed crl state is surfaced as degraded`() {
        val report = reducer.reduce(
            baseArtifacts(
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.ERROR,
                    summary = "Online CRL refresh failed; built-in revocation snapshot was used.",
                    detail = "CRL refresh timed out.",
                    cacheEntries = 1,
                    usedCache = true,
                    usingCacheFallback = true,
                ),
            ),
        )

        assertTrue(report.sections.single { it.title == "Trust" }.items.any {
            it.title == "CRL" &&
                    it.body.contains("Built-in snapshot") &&
                    it.body.contains("timed out")
        })
        assertTrue(report.signals.any { it.label == "CRL" && it.value == "Built-in" && it.level == TeeSignalLevel.WARN })
    }

    @Test
    fun `provisioned rkp does not stay green when local chain fails`() {
        val report = reducer.reduce(
            baseArtifacts(
                trust = CertificateTrustResult(
                    trustRoot = TeeTrustRoot.GOOGLE,
                    chainLength = 3,
                    chainSignatureValid = false,
                    googleRootMatched = true,
                ),
                rkp = TeeRkpState(
                    provisioned = true,
                    serverSigned = true,
                    validityDays = 30,
                ),
            ),
        )

        assertEquals(TeeSignalLevel.FAIL, report.localTrustChainLevel)
        assertEquals(
            TeeSignalLevel.FAIL,
            report.sections.single { it.title == "Trust" }.items.single { it.title == "RKP" }.level
        )
        assertTrue(report.trustSummary.contains("invalid local chain"))
    }

    @Test
    fun `rkp issuance count no longer creates custom soft anomaly`() {
        val report = reducer.reduce(
            baseArtifacts(
                rkp = TeeRkpState(
                    provisioned = true,
                    serverSigned = true,
                    abuseLevel = TeeSignalLevel.INFO,
                    abuseSummary = "Provisioning info reported approximately 1200 short-lived certificates in the last 30 days.",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertTrue(report.sections.none { section ->
            section.items.any { it.title == "RKP issuance" }
        })
    }

    @Test
    fun `soter skip stays local warning without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                soter = TeeSoterState(
                    serviceReachable = false,
                    keyPrepared = false,
                    signSessionAvailable = false,
                    available = false,
                    damaged = false,
                    summary = "Soter Treble service was not reachable; probe skipped.",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(0, report.supplementaryIndicatorCount)
        assertEquals("Attestation, trust path, and revocation checks line up.", report.summary)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Soter" &&
                    it.body.contains("probe skipped", ignoreCase = true) &&
                    it.level == TeeSignalLevel.WARN
        })
    }

    @Test
    fun `soter key or signing failure becomes tampered verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                soter = TeeSoterState(
                    serviceReachable = true,
                    keyPrepared = false,
                    signSessionAvailable = false,
                    available = false,
                    damaged = true,
                    summary = "Soter key preparation failed after the Treble service became reachable.",
                ),
            ),
        )

        assertEquals(TeeVerdict.TAMPERED, report.verdict)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Soter" &&
                    it.body.contains("Soter key preparation failed", ignoreCase = true) &&
                    it.level == TeeSignalLevel.FAIL
        })
        assertTrue(report.signals.any {
            it.label == "Signals" &&
                    it.value.contains("1 policy hard")
        })
    }

    @Test
    fun `abnormal soter environment becomes local warning and yellows card state`() {
        val report = reducer.reduce(
            baseArtifacts(
                soter = TeeSoterState(
                    serviceReachable = false,
                    keyPrepared = false,
                    signSessionAvailable = false,
                    available = false,
                    damaged = false,
                    abnormalEnvironment = true,
                    summary = "Abnormal Soter environment: Simplified Chinese locale on a likely Soter-supporting device, but PackageManager could not resolve com.tencent.soter.soterserver.",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertEquals(TeeSignalLevel.WARN, report.supplementaryReviewLevel)
        assertTrue(report.summary.contains("abnormal soter environment", ignoreCase = true))
        assertTrue(report.signals.any {
            it.label == "Signals" &&
                    it.value.contains("1 local")
        })
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Soter" &&
                    it.body.contains("abnormal soter environment", ignoreCase = true) &&
                    it.level == TeeSignalLevel.WARN
        })
    }
}
