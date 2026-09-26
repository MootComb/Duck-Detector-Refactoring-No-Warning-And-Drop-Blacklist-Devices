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

package com.eltavine.duckdetector.features.tee.presentation

import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import com.eltavine.duckdetector.capability.attestation.domain.TeeTrustRoot
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceItem
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceSection
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceSectionKind
import com.eltavine.duckdetector.features.tee.domain.TeeGrantProbe
import com.eltavine.duckdetector.features.tee.domain.TeeReport
import com.eltavine.duckdetector.features.tee.domain.TeeScanStage
import com.eltavine.duckdetector.features.tee.domain.TeeSignal
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict
import org.junit.Assert.assertEquals
import org.junit.Test

class TeeCardModelMapperGrantTest {

    private val mapper = TeeCardModelMapper()

    @Test
    fun `matched grant isolated-domain split escalates aligned tee card to danger`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "Grant isolated-domain certificate-chain narrative split detected. Attestation and trust-path checks still aligned.",
                summaryGrant = grant(TeeGrantProbe.ISOLATED_DOMAIN, "Grant isolated-domain certificate-chain narrative split detected. Attestation and trust-path checks still aligned."),
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
                signals = listOf(
                    TeeSignal(
                        "Grant isolated-domain",
                        "Matched",
                        TeeSignalLevel.FAIL,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        kind = TeeEvidenceSectionKind.CHECKS,
                        items = listOf(
                            TeeEvidenceItem(
                                "Grant isolated-domain",
                                "Matched kind=ISOLATED_CHAIN_SPLIT • mismatchIndex=2 • owner=3 grantee=2",
                                TeeSignalLevel.FAIL,
                                grant = grant(TeeGrantProbe.ISOLATED_DOMAIN, "Matched kind=ISOLATED_CHAIN_SPLIT • mismatchIndex=2 • owner=3 grantee=2"),
                            ),
                        ),
                    ),
                ),
                certificates = emptyList(),
            ),
            isExpanded = false,
        )

        assertEquals(DetectorStatus.danger(), model.status)
    }

    @Test
    fun `grant isolated-domain key visibility divergence escalates aligned tee card to danger`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "Grant isolated-domain key visibility divergence detected. Attestation and trust-path checks still aligned.",
                summaryGrant = grant(TeeGrantProbe.ISOLATED_DOMAIN, "Grant isolated-domain key visibility divergence detected. Attestation and trust-path checks still aligned."),
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
                signals = listOf(
                    TeeSignal(
                        "Grant isolated-domain",
                        "Unavailable",
                        TeeSignalLevel.FAIL,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        kind = TeeEvidenceSectionKind.CHECKS,
                        items = listOf(
                            TeeEvidenceItem(
                                "Grant isolated-domain",
                                "Unavailable kind=ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN • private grant failed: ServiceSpecificException(code 7): No key found by the given alias",
                                TeeSignalLevel.FAIL,
                                grant = grant(TeeGrantProbe.ISOLATED_DOMAIN, "Unavailable kind=ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN • private grant failed: ServiceSpecificException(code 7): No key found by the given alias"),
                            ),
                        ),
                    ),
                ),
                certificates = emptyList(),
            ),
            isExpanded = false,
        )

        assertEquals(DetectorStatus.danger(), model.status)
    }

    @Test
    fun `grant caller binding failure escalates aligned tee card to danger`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "Grant handle remained readable by its non-grantee owner. Attestation and trust-path checks still aligned.",
                summaryGrant = grant(TeeGrantProbe.CALLER_BINDING, "Grant handle remained readable by its non-grantee owner. Attestation and trust-path checks still aligned."),
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
                signals = listOf(
                    TeeSignal("Grant caller binding", "Matched", TeeSignalLevel.FAIL),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        kind = TeeEvidenceSectionKind.CHECKS,
                        items = listOf(
                            TeeEvidenceItem(
                                "Grant caller binding",
                                "Matched kind=NON_GRANTEE_READBACK_ALLOWED uid=99001 ownerReplay=true",
                                TeeSignalLevel.FAIL,
                                grant = grant(TeeGrantProbe.CALLER_BINDING, "Matched kind=NON_GRANTEE_READBACK_ALLOWED uid=99001 ownerReplay=true"),
                            ),
                        ),
                    ),
                ),
                certificates = emptyList(),
            ),
            isExpanded = false,
        )

        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals(
            "Grant handle caller binding failed; open TEE details for stage diagnostics.",
            model.findingDetail,
        )
    }

    @Test
    fun `grant isolated-domain private readback crash shows warning card and compact finding detail`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "Grant isolated-domain isolated private readback crashed after grant succeeded. Attestation and trust-path checks still aligned.",
                summaryGrant = grant(TeeGrantProbe.ISOLATED_DOMAIN, "Grant isolated-domain isolated private readback crashed after grant succeeded. Attestation and trust-path checks still aligned."),
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.WARN,
                signals = listOf(
                    TeeSignal(
                        "Grant isolated-domain",
                        "Warn",
                        TeeSignalLevel.WARN,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        kind = TeeEvidenceSectionKind.CHECKS,
                        items = listOf(
                            TeeEvidenceItem(
                                "Grant isolated-domain",
                                "Grant isolated-domain isolated private readback crashed after grant succeeded. kind=ISOLATED_PRIVATE_READBACK_CRASH owner=3 uid=99001",
                                TeeSignalLevel.WARN,
                                grant = grant(TeeGrantProbe.ISOLATED_DOMAIN, "Grant isolated-domain isolated private readback crashed after grant succeeded. kind=ISOLATED_PRIVATE_READBACK_CRASH owner=3 uid=99001"),
                                hiddenCopyText = "java.lang.reflect.InvocationTargetException\nCaused by: android.os.ServiceSpecificException: system/security/keystore2/src/service.rs:157: while trying to load key info.\n\nCaused by:\n    0: No legacy keys for key descriptor.\n    1: Error::Rc(r#KEY_NOT_FOUND) (code 7)",
                            ),
                        ),
                    ),
                ),
                certificates = emptyList(),
            ),
            isExpanded = false,
        )

        assertEquals(DetectorStatus.warning(), model.status)
        assertEquals(
            "Grant isolated-domain runtime crash; open TEE details for stage diagnostics.",
            model.findingDetail,
        )
        assertEquals(
            "java.lang.reflect.InvocationTargetException\nCaused by: android.os.ServiceSpecificException: system/security/keystore2/src/service.rs:157: while trying to load key info.\n\nCaused by:\n    0: No legacy keys for key descriptor.\n    1: Error::Rc(r#KEY_NOT_FOUND) (code 7)",
            model.factGroups.single().rows.single().hiddenCopyText,
        )
    }

    @Test
    fun `matched grant self-domain split escalates aligned tee card to danger`() {
        val longGrantSummary =
            "Grant self-domain certificate-chain split detected. " +
                "Public: clean | Hidden: clean | Private: owner=3 grant=2 mismatchIndex=2. " +
                "Attestation and trust-path checks still aligned."
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = longGrantSummary,
                summaryGrant = grant(TeeGrantProbe.SELF_DOMAIN, longGrantSummary),
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
                signals = listOf(
                    TeeSignal(
                        "Grant self-domain",
                        "Matched",
                        TeeSignalLevel.FAIL,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        kind = TeeEvidenceSectionKind.CHECKS,
                        items = listOf(
                            TeeEvidenceItem(
                                "Grant self-domain",
                                "Matched kind=SELF_CHAIN_SPLIT owner=3 grant=2 mismatchIndex=2",
                                TeeSignalLevel.FAIL,
                                grant = grant(TeeGrantProbe.SELF_DOMAIN, "Matched kind=SELF_CHAIN_SPLIT owner=3 grant=2 mismatchIndex=2"),
                            ),
                        ),
                    ),
                ),
                certificates = emptyList(),
            ),
            isExpanded = false,
        )

        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals(longGrantSummary, model.summary)
        assertEquals(
            "Grant self-domain certificate chain diverged; open TEE details for stage diagnostics.",
            model.findingDetail,
        )
    }

    @Test
    fun `matched grant self-domain key visibility divergence escalates aligned tee card to danger`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "Grant self-domain key visibility divergence detected. Attestation and trust-path checks still aligned.",
                summaryGrant = grant(TeeGrantProbe.SELF_DOMAIN, "Grant self-domain key visibility divergence detected. Attestation and trust-path checks still aligned."),
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
                signals = listOf(
                    TeeSignal(
                        "Grant self-domain",
                        "Unavailable",
                        TeeSignalLevel.FAIL,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        kind = TeeEvidenceSectionKind.CHECKS,
                        items = listOf(
                            TeeEvidenceItem(
                                "Grant self-domain",
                                "Unavailable kind=SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN owner=4 • private grant failed: ServiceSpecificException(code 7): No key found by the given alias",
                                TeeSignalLevel.FAIL,
                                grant = grant(TeeGrantProbe.SELF_DOMAIN, "Unavailable kind=SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN owner=4 • private grant failed: ServiceSpecificException(code 7): No key found by the given alias"),
                            ),
                        ),
                    ),
                ),
                certificates = emptyList(),
            ),
            isExpanded = false,
        )

        assertEquals(DetectorStatus.danger(), model.status)
    }
}
