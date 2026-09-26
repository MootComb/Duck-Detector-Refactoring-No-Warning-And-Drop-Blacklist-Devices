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

import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainFullChainSplitResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainFullChainSplitResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGetKeyEntryAccessVectorBlindnessResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackResult
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TeeReportReducerGrantTest {

    private val reducer = TeeReportReducer()

    @Test
    fun `grant isolated-domain full-chain split becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                grantDomainFullChainSplit = GrantDomainFullChainSplitResult(
                    executed = true,
                    available = true,
                    splitDetected = true,
                    ownerChainLength = 3,
                    granteeChainLength = 2,
                    mismatchIndex = 2,
                    granteeUid = 99001,
                    anomalyKind = GrantDomainAnomalyKind.ISOLATED_CHAIN_SPLIT,
                    detail = "Public: clean • Private: matched lengthMismatch owner=3 grantee=2",
                    diagnosticCopyText = "isolated diagnostic\nat com.example.Grant.probe(Grant.kt:1)",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("Grant isolated-domain", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant isolated-domain" &&
                it.level == TeeSignalLevel.FAIL &&
                it.body.contains("Matched", ignoreCase = true) &&
                it.body.contains("kind=ISOLATED_CHAIN_SPLIT") &&
                it.body.contains("mismatchIndex=2") &&
                !it.body.contains("at com.example") &&
                it.hiddenCopyText?.contains("at com.example.Grant.probe") == true
        })
    }

    @Test
    fun `grant isolated-domain key not found after owner chain becomes supplementary review`() {
        val report = reducer.reduce(
            baseArtifacts(
                grantDomainFullChainSplit = GrantDomainFullChainSplitResult(
                    executed = true,
                    available = false,
                    splitDetected = false,
                    ownerChainLength = 3,
                    granteeUid = 99001,
                    anomalyKind = GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
                    detail = "Public: clean • Private: private grant failed: ServiceSpecificException(code 7): No key found by the given alias",
                    diagnosticCopyText = "isolated key-not-found\nat com.example.Grant.keyNotFound(Grant.kt:2)",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("Grant isolated-domain key visibility divergence", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant isolated-domain" &&
                it.level == TeeSignalLevel.FAIL &&
                it.body.contains("Unavailable", ignoreCase = true) &&
                it.body.contains("kind=ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN") &&
                it.body.contains("No key found by the given alias") &&
                !it.body.contains("at com.example") &&
                it.hiddenCopyText?.contains("at com.example.Grant.keyNotFound") == true
        })
    }

    @Test
    fun `grant isolated-domain private readback crash becomes warning supplementary review`() {
        val report = reducer.reduce(
            baseArtifacts(
                grantDomainFullChainSplit = GrantDomainFullChainSplitResult(
                    executed = true,
                    available = false,
                    ownerChainLength = 3,
                    granteeUid = 99001,
                    anomalyKind = GrantDomainAnomalyKind.ISOLATED_PRIVATE_READBACK_CRASH,
                    detail = "Private: isolated readback crashed after grant succeeded.",
                    diagnosticCopyText = """
                        java.lang.reflect.InvocationTargetException
                        Caused by: android.os.ServiceSpecificException: system/security/keystore2/src/service.rs:157: while trying to load key info.

                        Caused by:
                            0: No legacy keys for key descriptor.
                            1: Error::Rc(r#KEY_NOT_FOUND) (code 7)
                    """.trimIndent(),
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertEquals(TeeSignalLevel.WARN, report.supplementaryReviewLevel)
        assertTrue(report.summary.contains("Grant isolated-domain", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant isolated-domain" &&
                it.level == TeeSignalLevel.WARN &&
                it.body.contains("isolated readback crashed", ignoreCase = true) &&
                it.hiddenCopyText?.contains("No legacy keys for key descriptor") == true
        })
    }

    @Test
    fun `grant isolated-domain unavailable state stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                grantDomainFullChainSplit = GrantDomainFullChainSplitResult(
                    executed = false,
                    detail = "Grant-domain full-chain split probe requires Android 16 or newer.",
                ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant isolated-domain" &&
                it.level == TeeSignalLevel.INFO &&
                it.body.contains("Unavailable", ignoreCase = true)
        })
    }

    @Test
    fun `grant caller binding non grantee readback becomes supplementary danger`() {
        val report = reducer.reduce(
            baseArtifacts(
                syntheticGrantGranteeBlindReadback = SyntheticGrantGranteeBlindReadbackResult(
                    executed = true,
                    available = true,
                    grantCreated = true,
                    granteeUid = 99001,
                    granteeReadSucceeded = true,
                    ownerReplaySucceeded = true,
                    anomalyKind = SyntheticGrantGranteeBlindReadbackAnomalyKind.NON_GRANTEE_READBACK_ALLOWED,
                    detail = "Private: non-grantee owner replay succeeded for isolated grant handle.",
                    diagnosticCopyText = "grant caller binding diagnostic",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertEquals(TeeSignalLevel.FAIL, report.supplementaryReviewLevel)
        assertTrue(report.summary.contains("Grant handle remained readable", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant caller binding" &&
                it.level == TeeSignalLevel.FAIL &&
                it.body.contains("NON_GRANTEE_READBACK_ALLOWED") &&
                it.body.contains("ownerReplay=true") &&
                it.hiddenCopyText == "grant caller binding diagnostic"
        })
    }

    @Test
    fun `grant caller binding rejected owner replay stays clean`() {
        val report = reducer.reduce(
            baseArtifacts(
                syntheticGrantGranteeBlindReadback = SyntheticGrantGranteeBlindReadbackResult(
                    executed = true,
                    available = true,
                    grantCreated = true,
                    granteeUid = 99001,
                    granteeReadSucceeded = true,
                    anomalyKind = SyntheticGrantGranteeBlindReadbackAnomalyKind.NONE,
                    detail = "Private: owner replay rejected with KEY_NOT_FOUND.",
                ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant caller binding" &&
                it.level == TeeSignalLevel.PASS &&
                it.body.contains("ownerReplay=KEY_NOT_FOUND")
        })
    }

    @Test
    fun `grant access vector missing get info readback becomes supplementary danger`() {
        val report = reducer.reduce(
            baseArtifacts(
                syntheticGrantGetKeyEntryAccessVectorBlindness =
                    SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                        executed = true,
                        available = true,
                        grantCreated = true,
                        granteeUid = 99001,
                        accessVector = 0x100,
                        granteeReadSucceeded = true,
                        anomalyKind =
                            SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.GET_KEY_ENTRY_WITHOUT_GET_INFO_ALLOWED,
                        detail = "Private: grantee getKeyEntry(GRANT) succeeded without GET_INFO.",
                        diagnosticCopyText = "grant access-vector diagnostic",
                    ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertEquals(TeeSignalLevel.FAIL, report.supplementaryReviewLevel)
        assertTrue(report.summary.contains("without GET_INFO", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant access vector" &&
                it.level == TeeSignalLevel.FAIL &&
                it.body.contains("GET_KEY_ENTRY_WITHOUT_GET_INFO_ALLOWED") &&
                it.body.contains("accessVector=256") &&
                it.hiddenCopyText == "grant access-vector diagnostic"
        })
    }

    @Test
    fun `grant access vector permission denied readback stays clean`() {
        val report = reducer.reduce(
            baseArtifacts(
                syntheticGrantGetKeyEntryAccessVectorBlindness =
                    SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                        executed = true,
                        available = true,
                        grantCreated = true,
                        granteeUid = 99001,
                        accessVector = 0x100,
                        anomalyKind = SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.NONE,
                        detail = "Private: grantee getKeyEntry(GRANT) rejected with PERMISSION_DENIED.",
                    ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant access vector" &&
                it.level == TeeSignalLevel.PASS &&
                it.body.contains("granteeRead=PERMISSION_DENIED")
        })
    }

    @Test
    fun `grant self-domain full-chain split becomes supplementary review without changing attestation verdict`() {
        val report = reducer.reduce(
            baseArtifacts(
                grantSelfDomainFullChainSplit = GrantSelfDomainFullChainSplitResult(
                    executed = true,
                    available = true,
                    splitDetected = true,
                    ownerChainLength = 3,
                    grantChainLength = 2,
                    mismatchIndex = 2,
                    grantIdPresent = true,
                    anomalyKind = GrantSelfDomainAnomalyKind.SELF_CHAIN_SPLIT,
                    detail = "Public: clean • Private: matched lengthMismatch owner=3 grantee=2",
                    diagnosticCopyText = "self diagnostic\nat com.example.Grant.selfSplit(Grant.kt:3)",
                ),
            ),
        )

        assertEquals(TeeVerdict.CONSISTENT, report.verdict)
        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("Grant self-domain certificate-chain split", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant self-domain" &&
                it.level == TeeSignalLevel.FAIL &&
                it.body.contains("Matched", ignoreCase = true) &&
                it.body.contains("kind=SELF_CHAIN_SPLIT") &&
                it.body.contains("mismatchIndex=2") &&
                !it.body.contains("at com.example") &&
                it.hiddenCopyText?.contains("at com.example.Grant.selfSplit") == true
        })
    }

    @Test
    fun `grant self-domain owner-visible key-not-found state becomes supplementary failure`() {
        val report = reducer.reduce(
            baseArtifacts(
                grantSelfDomainFullChainSplit = GrantSelfDomainFullChainSplitResult(
                    executed = true,
                    ownerChainLength = 4,
                    anomalyKind = GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
                    detail = "Public: clean • Private: private grant failed: ServiceSpecificException(code 7): No key found by the given alias",
                    diagnosticCopyText = "self key-not-found\nat com.example.Grant.selfKeyNotFound(Grant.kt:4)",
                ),
            ),
        )

        assertEquals(1, report.supplementaryIndicatorCount)
        assertTrue(report.summary.contains("Grant self-domain key visibility divergence", ignoreCase = true))
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant self-domain" &&
                it.level == TeeSignalLevel.FAIL &&
                it.body.contains("Unavailable", ignoreCase = true) &&
                it.body.contains("kind=SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN") &&
                it.body.contains("owner=4") &&
                it.body.contains("No key found by the given alias") &&
                !it.body.contains("at com.example") &&
                it.hiddenCopyText?.contains("at com.example.Grant.selfKeyNotFound") == true
        })
    }

    @Test
    fun `grant self-domain ordinary unavailable state stays informational`() {
        val report = reducer.reduce(
            baseArtifacts(
                grantSelfDomainFullChainSplit = GrantSelfDomainFullChainSplitResult(
                    executed = false,
                    detail = "private grant failed: IllegalStateException: transient service unavailable",
                ),
            ),
        )

        assertEquals(0, report.supplementaryIndicatorCount)
        assertTrue(report.sections.single { it.title == "Checks" }.items.any {
            it.title == "Grant self-domain" &&
                it.level == TeeSignalLevel.INFO &&
                it.body.contains("Unavailable", ignoreCase = true) &&
                it.body.contains("transient service unavailable")
            })
    }
}
