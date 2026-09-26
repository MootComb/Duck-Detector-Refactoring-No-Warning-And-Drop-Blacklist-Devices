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
import com.eltavine.duckdetector.features.tee.domain.TeeReport
import com.eltavine.duckdetector.features.tee.domain.TeeScanStage
import com.eltavine.duckdetector.features.tee.domain.TeeSignal
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict
import org.junit.Assert.assertEquals
import org.junit.Test

class TeeCardModelMapperSupplementaryTest {

    private val mapper = TeeCardModelMapper()

    @Test
    fun `matched update persistence stale narrative escalates aligned tee card to danger`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "UpdateSubcomponent stale TEE response persistence detected. Attestation and trust-path checks still aligned.",
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 1,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
                signals = listOf(
                    TeeSignal(
                        "Update persistence",
                        "Matched",
                        TeeSignalLevel.FAIL,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        kind = TeeEvidenceSectionKind.CHECKS,
                        items = listOf(
                            TeeEvidenceItem(
                                "Update persistence",
                                "Matched kind=STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE retained=1 prior=3 post=2",
                                TeeSignalLevel.FAIL,
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
    fun `structured supplementary failure drives danger even when warning row appears first`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.CONSISTENT,
                tier = TeeTier.TEE,
                headline = "Attestation aligned; local probes need review",
                summary = "UpdateSubcomponent stale TEE response persistence detected. Attestation and trust-path checks still aligned.",
                collapsedSummary = "Aligned • local review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Local trust path",
                tamperScore = 10,
                evidenceCount = 2,
                supplementaryIndicatorCount = 2,
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
                signals = listOf(
                    TeeSignal(
                        "Signals",
                        "0 policy hard • 0 policy review • 2 local",
                        TeeSignalLevel.FAIL,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        kind = TeeEvidenceSectionKind.CHECKS,
                        items = listOf(
                            TeeEvidenceItem(
                                "Soter",
                                "Review abnormal Soter environment.",
                                TeeSignalLevel.WARN,
                            ),
                            TeeEvidenceItem(
                                "Update persistence",
                                "Matched kind=STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE retained=1",
                                TeeSignalLevel.FAIL,
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
    fun `structured supplementary failure drives danger even under suspicious verdict`() {
        val model = mapper.map(
            report = TeeReport(
                stage = TeeScanStage.READY,
                verdict = TeeVerdict.SUSPICIOUS,
                tier = TeeTier.TEE,
                headline = "Policy-backed attestation evidence needs review",
                summary = "Provisioning info was not adjacent to the trusted attestation certificate.",
                collapsedSummary = "1 policy review",
                trustRoot = TeeTrustRoot.GOOGLE,
                trustSummary = "Google root, chain needs review",
                tamperScore = 18,
                evidenceCount = 2,
                supplementaryIndicatorCount = 1,
                supplementaryReviewLevel = TeeSignalLevel.FAIL,
                signals = listOf(
                    TeeSignal(
                        "Signals",
                        "0 policy hard • 1 policy review • 1 local",
                        TeeSignalLevel.FAIL,
                    ),
                ),
                sections = listOf(
                    TeeEvidenceSection(
                        kind = TeeEvidenceSectionKind.TRUST,
                        items = listOf(
                            TeeEvidenceItem(
                                "Chain layout",
                                "Provisioning info was not adjacent to the trusted attestation certificate.",
                                TeeSignalLevel.WARN,
                            ),
                        ),
                    ),
                    TeeEvidenceSection(
                        kind = TeeEvidenceSectionKind.CHECKS,
                        items = listOf(
                            TeeEvidenceItem(
                                "Update persistence",
                                "Matched kind=STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE retained=1",
                                TeeSignalLevel.FAIL,
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
