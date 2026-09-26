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

import com.eltavine.duckdetector.capability.attestation.domain.TeeTrustRoot
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceSectionKind
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceTopic
import com.eltavine.duckdetector.features.tee.domain.TeeGrantProbe
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkMode
import com.eltavine.duckdetector.features.tee.domain.TeeReport
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict
import com.eltavine.duckdetector.features.tee.domain.toDetectorStatus
import com.eltavine.duckdetector.features.tee.presentation.model.TeeCardModel
import com.eltavine.duckdetector.features.tee.presentation.model.TeeCertificateSummaryModel
import com.eltavine.duckdetector.features.tee.presentation.model.TeeFactGroupModel
import com.eltavine.duckdetector.features.tee.presentation.model.TeeFactIcon
import com.eltavine.duckdetector.features.tee.presentation.model.TeeFactRowModel
import com.eltavine.duckdetector.features.tee.presentation.model.TeeFooterActionId
import com.eltavine.duckdetector.features.tee.presentation.model.TeeFooterActionModel
import com.eltavine.duckdetector.features.tee.presentation.model.TeeHeaderFact
import com.eltavine.duckdetector.features.tee.presentation.model.TeeHeaderFactModel
import com.eltavine.duckdetector.features.tee.presentation.model.TeeHighlightSignalModel
import com.eltavine.duckdetector.features.tee.presentation.model.TeeNetworkStateModel

class TeeCardModelMapper {

    fun map(
        report: TeeReport,
        isExpanded: Boolean,
    ): TeeCardModel {
        val status = report.toDetectorStatus()
        return TeeCardModel(
            title = "TEE",
            subtitle = report.trustSummary,
            status = status,
            verdict = report.headline,
            summary = report.summary,
            findingDetail = report.topFindingDetail(),
            rkpBadgeLabel = rkpBadgeLabel(report),
            isExpanded = isExpanded,
            headerFacts = buildHeaderFacts(report, status),
            highlightSignals = report.signals.take(4).map { signal ->
                TeeHighlightSignalModel(
                    label = signal.label,
                    value = signal.value,
                    status = signal.level.toDetectorStatus(),
                )
            },
            factGroups = report.sections.map { section ->
                TeeFactGroupModel(
                    title = section.title,
                    rows = section.items.map { item ->
                        TeeFactRowModel(
                            icon = iconFor(section.kind, item.topic),
                            label = item.title,
                            value = item.body,
                            status = item.level.toDetectorStatus(),
                            hiddenCopyText = item.hiddenCopyText,
                        )
                    },
                )
            },
            certificateSummary = TeeCertificateSummaryModel(
                label = "Certificate chain",
                count = report.certificates.size.toString(),
                certificates = report.certificates,
            ),
            actions = buildActions(report),
            networkState = TeeNetworkStateModel(
                label = "Network",
                summary = report.networkState.summary,
                status = when (report.networkState.mode) {
                    TeeNetworkMode.ACTIVE -> DetectorStatus.allClear()
                    TeeNetworkMode.CONSENT_REQUIRED -> DetectorStatus.info(InfoKind.SUPPORT)
                    TeeNetworkMode.ERROR -> DetectorStatus.info(InfoKind.ERROR)
                    TeeNetworkMode.SKIPPED -> DetectorStatus.info(InfoKind.SUPPORT)
                    TeeNetworkMode.INACTIVE -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            exportText = report.exportText,
        )
    }

    private fun buildHeaderFacts(
        report: TeeReport,
        status: DetectorStatus,
    ): List<TeeHeaderFactModel> {
        val scoreStatus = if (report.tamperScore > 0) {
            when {
                report.tamperScore >= 60 -> DetectorStatus.danger()
                report.tamperScore >= 24 -> DetectorStatus.warning()
                else -> DetectorStatus.allClear()
            }
        } else {
            DetectorStatus.allClear()
        }
        return listOf(
            TeeHeaderFactModel(TeeHeaderFact.VERDICT, verdictValue(report), status),
            TeeHeaderFactModel(TeeHeaderFact.TIER, report.tier.displayName(), report.tierStatus()),
            TeeHeaderFactModel(TeeHeaderFact.TRUST, trustRootValue(report), report.trustStatus()),
            TeeHeaderFactModel(TeeHeaderFact.SCORE, report.tamperScore.toString(), scoreStatus),
        )
    }

    private fun buildActions(report: TeeReport): List<TeeFooterActionModel> {
        val actions = mutableListOf(
            TeeFooterActionModel(TeeFooterActionId.DETAILS, "Details"),
        )
        if (report.certificates.isNotEmpty()) {
            actions += TeeFooterActionModel(
                id = TeeFooterActionId.CERTIFICATES,
                label = "Certificates",
                counter = report.certificates.size.toString(),
            )
        }
        return actions
    }

    private fun verdictValue(report: TeeReport): String = when (report.verdict) {
        TeeVerdict.LOADING -> "Scanning"
        TeeVerdict.CONSISTENT -> if (report.supplementaryIndicatorCount > 0) {
            "Aligned + review"
        } else {
            "Aligned"
        }
        TeeVerdict.SUSPICIOUS -> "Review"
        TeeVerdict.TAMPERED -> "Tampered"
        TeeVerdict.BROKEN -> "Broken"
        TeeVerdict.INCONCLUSIVE -> "Mixed"
    }

    private fun rkpBadgeLabel(report: TeeReport): String? =
        if (report.rkpState.provisioned && report.localTrustChainLevel == TeeSignalLevel.PASS) {
            "RKP"
        } else {
            null
        }

    private fun TeeReport.topFindingDetail(): String? {
        // Only a summary that quotes a grant probe's item leads to a grant finding.
        val summaryGrant = summaryGrant ?: return null
        // Grant stage details can include Java/hidden/private summaries. Keep that audit text inside
        // the TEE card; Dashboard top findings should be a short routing hint, not a diagnostic dump.
        // Grant 阶段细节可能包含 Java/hidden/private 摘要。审计文本留在 TEE 卡片内；Dashboard 顶层 finding 只给短路由提示，不承载诊断 dump。
        val grantItems = sections.asSequence().flatMap { section -> section.items.asSequence() }
        val grantFailure = grantItems.firstOrNull { it.grant != null && it.level == TeeSignalLevel.FAIL }
            ?: grantItems.firstOrNull { it.grant != null && it.level == TeeSignalLevel.WARN }
            ?: return null
        val grant = checkNotNull(grantFailure.grant)
        val keyVisibilityDiverged =
            summaryGrant.namesKeyVisibility || grant.namesKeyVisibility || grant.namesMissingKey
        return when (grant.probe) {
            TeeGrantProbe.SELF_DOMAIN -> if (keyVisibilityDiverged) {
                "Grant self-domain key visibility diverged; open TEE details for stage diagnostics."
            } else {
                "Grant self-domain certificate chain diverged; open TEE details for stage diagnostics."
            }
            TeeGrantProbe.ISOLATED_DOMAIN -> if (keyVisibilityDiverged) {
                "Grant isolated-domain key visibility diverged; open TEE details for stage diagnostics."
            } else if (grantFailure.level == TeeSignalLevel.WARN) {
                "Grant isolated-domain runtime crash; open TEE details for stage diagnostics."
            } else {
                "Grant isolated-domain certificate chain diverged; open TEE details for stage diagnostics."
            }
            TeeGrantProbe.CALLER_BINDING ->
                "Grant handle caller binding failed; open TEE details for stage diagnostics."
        }
    }

    private fun trustRootValue(report: TeeReport): String = when (report.trustRoot) {
        TeeTrustRoot.GOOGLE_RKP -> "Google"
        TeeTrustRoot.GOOGLE -> "Google"
        TeeTrustRoot.AOSP -> "AOSP"
        TeeTrustRoot.FACTORY -> "Factory"
        TeeTrustRoot.UNKNOWN -> "Unknown"
    }

    private fun iconFor(
        section: TeeEvidenceSectionKind,
        topic: TeeEvidenceTopic?,
    ): TeeFactIcon {
        return when (section) {
            TeeEvidenceSectionKind.TRUST -> when (topic) {
                TeeEvidenceTopic.TRUST_ROOT -> TeeFactIcon.TRUST
                TeeEvidenceTopic.RKP -> TeeFactIcon.RKP
                TeeEvidenceTopic.CRL -> TeeFactIcon.NETWORK
                else -> TeeFactIcon.CERTIFICATE
            }

            TeeEvidenceSectionKind.ATTESTATION -> when (topic) {
                TeeEvidenceTopic.VERIFIED_BOOT,
                TeeEvidenceTopic.BOOT_CONSISTENCY -> TeeFactIcon.BOOT
                TeeEvidenceTopic.DEVICE_IDS -> TeeFactIcon.DEVICE
                TeeEvidenceTopic.USER_AUTH -> TeeFactIcon.AUTH
                TeeEvidenceTopic.APPLICATION -> TeeFactIcon.APP
                else -> TeeFactIcon.KEY
            }

            TeeEvidenceSectionKind.CHECKS -> when (topic) {
                TeeEvidenceTopic.TIMING -> TeeFactIcon.TIMING
                TeeEvidenceTopic.STRONGBOX -> TeeFactIcon.STRONGBOX
                TeeEvidenceTopic.NATIVE -> TeeFactIcon.NATIVE
                TeeEvidenceTopic.SOTER -> TeeFactIcon.SOTER
                TeeEvidenceTopic.INDICATORS -> TeeFactIcon.WARNING
                else -> TeeFactIcon.KEYSTORE
            }
        }
    }

    private fun TeeReport.tierStatus(): DetectorStatus = when (tier) {
        com.eltavine.duckdetector.capability.attestation.domain.TeeTier.STRONGBOX,
        com.eltavine.duckdetector.capability.attestation.domain.TeeTier.TEE -> DetectorStatus.allClear()

        com.eltavine.duckdetector.capability.attestation.domain.TeeTier.SOFTWARE -> DetectorStatus.warning()
        com.eltavine.duckdetector.capability.attestation.domain.TeeTier.NONE -> DetectorStatus.danger()
        com.eltavine.duckdetector.capability.attestation.domain.TeeTier.UNKNOWN -> DetectorStatus.info(
            InfoKind.SUPPORT
        )
    }

    private fun TeeReport.trustStatus(): DetectorStatus = when {
        localTrustChainLevel == TeeSignalLevel.FAIL -> DetectorStatus.danger()
        localTrustChainLevel == TeeSignalLevel.WARN -> DetectorStatus.warning()
        trustRoot == TeeTrustRoot.GOOGLE || trustRoot == TeeTrustRoot.GOOGLE_RKP -> DetectorStatus.allClear()
        trustRoot == TeeTrustRoot.AOSP -> DetectorStatus.warning()
        else -> DetectorStatus.info(InfoKind.SUPPORT)
    }

    private fun TeeSignalLevel.toDetectorStatus(): DetectorStatus = when (this) {
        TeeSignalLevel.PASS -> DetectorStatus.allClear()
        TeeSignalLevel.INFO -> DetectorStatus.info(InfoKind.SUPPORT)
        TeeSignalLevel.WARN -> DetectorStatus.warning()
        TeeSignalLevel.FAIL -> DetectorStatus.danger()
    }

    private fun com.eltavine.duckdetector.capability.attestation.domain.TeeTier.displayName(): String =
        when (this) {
            com.eltavine.duckdetector.capability.attestation.domain.TeeTier.UNKNOWN -> "Unknown"
            com.eltavine.duckdetector.capability.attestation.domain.TeeTier.NONE -> "None"
            com.eltavine.duckdetector.capability.attestation.domain.TeeTier.SOFTWARE -> "Software"
            com.eltavine.duckdetector.capability.attestation.domain.TeeTier.TEE -> "TEE"
            com.eltavine.duckdetector.capability.attestation.domain.TeeTier.STRONGBOX -> "StrongBox"
        }
}
