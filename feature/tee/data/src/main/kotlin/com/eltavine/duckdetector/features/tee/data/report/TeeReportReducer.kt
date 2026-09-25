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

import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceItem
import com.eltavine.duckdetector.features.tee.domain.TeeReport
import com.eltavine.duckdetector.features.tee.domain.TeeScanStage
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SupplementaryAttestationInfoAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentStaleResponseAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2PostProcessingAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.VintfKeyMintVersionAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.rkp.RkpProvisionedManufacturerAnomalyKind

class TeeReportReducer(
    private val exportFormatter: TeeExportFormatter = TeeExportFormatter(),
) {

    fun reduce(artifacts: TeeScanArtifacts): TeeReport {
        val patchState = buildPatchState(artifacts)
        val policyHardIndicators = collectPolicyHardIndicators(artifacts)
        val policySoftIndicators = collectPolicySoftIndicators(artifacts, patchState)
        val supplementaryIndicators = collectSupplementaryIndicators(artifacts)
        val effectiveTier = effectiveTier(artifacts)
        val verdict = determineVerdict(artifacts, policyHardIndicators, policySoftIndicators)
        val supplementaryDangerCount =
            supplementaryIndicators.count { it.level == TeeSignalLevel.FAIL }
        val supplementaryWarningCount =
            supplementaryIndicators.count { it.level == TeeSignalLevel.WARN }
        val tamperScore = (
                (policyHardIndicators.size * 28) +
                        (policySoftIndicators.size * 8) +
                        (supplementaryDangerCount * 10) +
                        (supplementaryWarningCount * 4)
                ).coerceAtMost(100)
        val sections = buildSections(
            artifacts = artifacts,
            patchState = patchState,
            policyHardIndicators = policyHardIndicators,
            policySoftIndicators = policySoftIndicators,
            supplementaryIndicators = supplementaryIndicators,
        )
        val normalizedTrustRoot = normalizeTrustRoot(artifacts.trust.trustRoot)
        val report = TeeReport(
            stage = TeeScanStage.READY,
            verdict = verdict,
            tier = effectiveTier,
            headline = headlineFor(verdict, supplementaryIndicators),
            summary = summaryFor(
                verdict = verdict,
                artifacts = artifacts,
                policyHardIndicators = policyHardIndicators,
                policySoftIndicators = policySoftIndicators,
                supplementaryIndicators = supplementaryIndicators,
            ),
            collapsedSummary = collapsedSummaryFor(
                verdict = verdict,
                policyHardIndicators = policyHardIndicators,
                policySoftIndicators = policySoftIndicators,
                supplementaryIndicators = supplementaryIndicators,
            ),
            trustRoot = normalizedTrustRoot,
            localTrustChainLevel = localTrustChainLevel(artifacts),
            trustSummary = trustSummaryFor(artifacts),
            tamperScore = tamperScore,
            evidenceCount = sections.sumOf { it.items.size },
            supplementaryIndicatorCount = supplementaryIndicators.size,
            supplementaryReviewLevel = supplementaryReviewLevel(supplementaryIndicators),
            signals = buildSignals(
                artifacts = artifacts,
                patchState = patchState,
                policyHardIndicators = policyHardIndicators,
                policySoftIndicators = policySoftIndicators,
                supplementaryIndicators = supplementaryIndicators,
            ),
            sections = sections,
            certificates = artifacts.snapshot.displayCertificates,
            rkpState = artifacts.rkp,
            patchState = patchState,
            soterState = artifacts.soter,
            networkState = artifacts.crl.networkState,
            exportText = "",
            failureMessage = artifacts.snapshot.errorMessage,
        )
        return report.copy(exportText = exportFormatter.format(report))
    }

    private fun collectSupplementaryIndicators(artifacts: TeeScanArtifacts): List<TeeEvidenceItem> {
        return buildList {
            if (artifacts.soter.abnormalEnvironment) {
                add(
                    fact(
                        "Soter environment",
                        artifacts.soter.summary,
                        TeeSignalLevel.WARN,
                    )
                )
            }
            val timingSideChannelSkipSignature = timingSideChannelSkipSignature(artifacts.timingSideChannel)
            if (timingSideChannelSkipSignature != null) {
                add(
                    fact(
                        "Timing side-channel",
                        timingSideChannelSkipSignature.summary,
                        timingSideChannelSkipSignature.level,
                    )
                )
            } else if (
                artifacts.timingSideChannel.measurementAvailable &&
                artifacts.timingSideChannel.ratioEligible &&
                artifacts.timingSideChannel.suspicious
            ) {
                add(
                    fact(
                        "Timing side-channel",
                        timingSideChannelSummary(artifacts),
                        TeeSignalLevel.WARN,
                    )
                )
            }
            if (generateModeAnomalyState(artifacts) == GenerateModeAnomalyState.MATCHED) {
                add(
                    fact(
                        "TEE Simulator generate-mode fingerprint",
                        "Matched TEE Simulator generate-mode fingerprint.",
                        TeeSignalLevel.FAIL,
                        hiddenCopyText = artifacts.generateModeParcelFingerprint.diagnosticCopyText,
                    )
                )
            }
            if (artifacts.vintfKeyMintVersion.anomalyKind == VintfKeyMintVersionAnomalyKind.MISMATCH) {
                // This is reported separately from the crypto capability row. A version/tier
                // identity mismatch means the target backend cannot be selected unambiguously;
                // it is evidence about identity, not evidence that an MGF1 operation executed.
                // 这里必须与 crypto capability 分开报告。版本/tier 身份冲突表示无法唯一选中
                // backend，它是“身份不一致”证据，不是“MGF1 已执行且失败”证据。
                val runtimeIdentityMismatch = keyMintRuntimeIdentityMismatch(artifacts)
                add(
                    fact(
                        if (runtimeIdentityMismatch) "KeyMint runtime identity" else "KeyMint VINTF",
                        if (runtimeIdentityMismatch) {
                            "Attestation and keymaster versions violate the AOSP single-runtime mapping. " +
                                vintfKeyMintVersionValue(artifacts)
                        } else {
                            "VINTF KeyMint version diverged from attestation. " +
                                vintfKeyMintVersionValue(artifacts)
                        },
                        TeeSignalLevel.FAIL,
                        hiddenCopyText = artifacts.vintfKeyMintVersion.diagnosticCopyText,
                    )
                )
            }
            // ATTEST_KEY 路径在 security_level.rs 里没有后处理调用点，所以这两类都是强本地证据：
            // RootOfTrust 在两条分支间分叉，或 RKP 路径的单侧延迟显著超过本机噪声
            // The ATTEST_KEY path has no post-processing call site in security_level.rs, so both of these are strong
            // local evidence: RootOfTrust forking between the arms, or one-sided RKP-path latency well above this
            // device's own noise.
            if (
                artifacts.postProcessing.anomalyKind ==
                    Keystore2PostProcessingAnomalyKind.ROOT_OF_TRUST_DIVERGENCE ||
                artifacts.postProcessing.anomalyKind ==
                    Keystore2PostProcessingAnomalyKind.TIMING_DETECTED
            ) {
                add(
                    fact(
                        "Cert post-processing",
                        postProcessingValue(artifacts),
                        TeeSignalLevel.FAIL,
                    )
                )
            }
            if (
                artifacts.rkpProvisionedManufacturer.anomalyKind ==
                    RkpProvisionedManufacturerAnomalyKind.MISMATCH
            ) {
                add(
                    fact(
                        "RKP manufacturer",
                        rkpProvisionedManufacturerValue(artifacts),
                        TeeSignalLevel.FAIL,
                    )
                )
            }
            // Grant checks are supplementary, but these two kinds are strong local evidence:
            // Grant 检测属于补充证据；但下面两类是强本地证据：
            // 1) chain split means owner alias and Domain.GRANT return different ordered certificate narratives.
            // 1) chain split 表示 owner alias 与 Domain.GRANT 返回了不同的有序证书叙事。
            // 2) key-not-found after owner chain means the alias exists in owner view but not in grant lookup.
            // 2) owner chain 后 key-not-found 表示 alias 存在于 owner 视图，却不存在于 grant 查找路径。
            when (artifacts.grantDomainFullChainSplit.anomalyKind) {
                GrantDomainAnomalyKind.ISOLATED_CHAIN_SPLIT -> {
                    add(
                        fact(
                            "Grant isolated-domain",
                            "Grant isolated-domain certificate-chain narrative split detected. " +
                                grantDomainFullChainSplitValue(artifacts),
                            TeeSignalLevel.FAIL,
                            hiddenCopyText = artifacts.grantDomainFullChainSplit.diagnosticCopyText
                                .takeIf { it.isNotBlank() },
                        )
                    )
                }

                GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN -> {
                    add(
                        fact(
                            "Grant isolated-domain",
                            "Grant isolated-domain key visibility divergence detected. " +
                                grantDomainFullChainSplitValue(artifacts),
                            TeeSignalLevel.FAIL,
                            hiddenCopyText = artifacts.grantDomainFullChainSplit.diagnosticCopyText
                                .takeIf { it.isNotBlank() },
                        )
                    )
                }

                GrantDomainAnomalyKind.ISOLATED_PRIVATE_READBACK_CRASH -> {
                    add(
                        fact(
                            "Grant isolated-domain",
                            "Grant isolated-domain isolated private readback crashed after grant succeeded. " +
                                grantDomainFullChainSplitValue(artifacts),
                            TeeSignalLevel.WARN,
                            hiddenCopyText = artifacts.grantDomainFullChainSplit.diagnosticCopyText
                                .takeIf { it.isNotBlank() },
                        )
                    )
                }

                GrantDomainAnomalyKind.NONE,
                GrantDomainAnomalyKind.UNAVAILABLE -> Unit
            }
            if (
                artifacts.syntheticGrantGranteeBlindReadback.anomalyKind ==
                SyntheticGrantGranteeBlindReadbackAnomalyKind.NON_GRANTEE_READBACK_ALLOWED
            ) {
                add(
                    fact(
                        "Grant caller binding",
                        "Grant handle remained readable by its non-grantee owner. " +
                            syntheticGrantGranteeBlindReadbackValue(artifacts),
                        TeeSignalLevel.FAIL,
                        hiddenCopyText = artifacts.syntheticGrantGranteeBlindReadback.diagnosticCopyText
                            .takeIf { it.isNotBlank() },
                    )
                )
            }
            if (
                artifacts.syntheticGrantGetKeyEntryAccessVectorBlindness.anomalyKind ==
                SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.GET_KEY_ENTRY_WITHOUT_GET_INFO_ALLOWED
            ) {
                add(
                    fact(
                        "Grant access vector",
                        "Domain.GRANT handle without GET_INFO still allowed getKeyEntry metadata readback. " +
                            syntheticGrantGetKeyEntryAccessVectorBlindnessValue(artifacts),
                        TeeSignalLevel.FAIL,
                        hiddenCopyText = artifacts.syntheticGrantGetKeyEntryAccessVectorBlindness.diagnosticCopyText
                            .takeIf { it.isNotBlank() },
                    )
                )
            }
            // self-domain removes the isolated-process policy variable; its key-not-found variant is treated like a visibility split.
            // self-domain 排除了 isolated-process 策略变量；其 key-not-found 变体按可见性断裂处理。
            when (artifacts.grantSelfDomainFullChainSplit.anomalyKind) {
                GrantSelfDomainAnomalyKind.SELF_CHAIN_SPLIT -> {
                    add(
                        fact(
                            "Grant self-domain",
                            "Grant self-domain certificate-chain split detected. " +
                                grantSelfDomainFullChainSplitValue(artifacts),
                            TeeSignalLevel.FAIL,
                            hiddenCopyText = artifacts.grantSelfDomainFullChainSplit.diagnosticCopyText
                                .takeIf { it.isNotBlank() },
                        )
                    )
                }

                GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN -> {
                    add(
                        fact(
                            "Grant self-domain",
                            "Grant self-domain key visibility divergence detected. " +
                                grantSelfDomainFullChainSplitValue(artifacts),
                            TeeSignalLevel.FAIL,
                            hiddenCopyText = artifacts.grantSelfDomainFullChainSplit.diagnosticCopyText
                                .takeIf { it.isNotBlank() },
                        )
                    )
                }

                GrantSelfDomainAnomalyKind.SELF_GRANT_ATTESTATION_APP_KEY_NOT_FOUND -> {
                    add(
                        fact(
                            "Grant self-domain",
                            "Grant self-domain custom-attestation visibility divergence detected. " +
                                grantSelfDomainFullChainSplitValue(artifacts),
                            TeeSignalLevel.FAIL,
                            hiddenCopyText = artifacts.grantSelfDomainFullChainSplit.diagnosticCopyText
                                .takeIf { it.isNotBlank() },
                        )
                    )
                }

                GrantSelfDomainAnomalyKind.NONE,
                GrantSelfDomainAnomalyKind.UNAVAILABLE -> Unit
            }
            if (artifacts.keystore2Hook.javaHookDetected) {
                add(
                    fact(
                        "Keystore2",
                        "Binder reply fingerprint matched a Java-hook style path.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.legacyKeystorePath.executed &&
                artifacts.legacyKeystorePath.legacyMaterialAvailable &&
                !artifacts.legacyKeystorePath.chainMatches
            ) {
                add(
                    fact(
                        "Legacy keystore",
                        "Legacy USRCERT_/CACERT_ path diverged from the Java KeyStore certificate chain.",
                        TeeSignalLevel.WARN
                    )
                )
            }
            if (artifacts.listEntriesConsistency.executed &&
                (artifacts.listEntriesConsistency.inconsistent || artifacts.listEntriesConsistency.badParcelableLikeCrash)
            ) {
                add(
                    fact(
                        "listEntries",
                        "containsAlias()/aliases() diverged or crashed with a BadParcelable-style path.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.listEntriesBatched.executed &&
                (artifacts.listEntriesBatched.cursorEchoed || artifacts.listEntriesBatched.expectedNextMissing)
            ) {
                add(
                    fact(
                        "listEntriesBatched",
                        "Keystore2 listEntriesBatched(startPastAlias) diverged from expected cursor semantics.",
                        if (artifacts.listEntriesBatched.cursorEchoed) TeeSignalLevel.FAIL else TeeSignalLevel.WARN
                    )
                )
            }
            if (artifacts.keyMetadataSemantics.executed &&
                (!artifacts.keyMetadataSemantics.usesKeyIdDomain || !artifacts.keyMetadataSemantics.aliasCleared)
            ) {
                add(
                    fact(
                        "Key metadata",
                        "Keystore2 metadata.key did not normalize to KEY_ID semantics.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.keyMetadataShape.executed &&
                (!artifacts.keyMetadataShape.modificationTimeValid || !artifacts.keyMetadataShape.hasOriginTag)
            ) {
                add(
                    fact(
                        "Key metadata",
                        "Keystore2 metadata omitted expected modification time or ORIGIN authorization tags.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.keyboxImport.executed && !artifacts.keyboxImport.markerPreserved) {
                add(
                    fact(
                        "Keybox import",
                        "Imported marker certificate came back rewritten.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.importKeyRetainedAttestationNarrative.executed &&
                artifacts.importKeyRetainedAttestationNarrative.retainedNarrativeDetected
            ) {
                add(
                    fact(
                        "ImportKey narrative",
                        "ImportKey retained attestation narrative detected.",
                        TeeSignalLevel.FAIL,
                    )
                )
            }
            when (artifacts.supplementaryAttestationInfo.anomalyKind) {
                SupplementaryAttestationInfoAnomalyKind.MISSING_ATTESTATION_MODULE_HASH -> {
                    add(
                        fact(
                            "Module hash",
                            "getSupplementaryAttestationInfo(MODULE_HASH) returned module info, but attestation omitted MODULE_HASH.",
                            TeeSignalLevel.WARN,
                            hiddenCopyText = artifacts.supplementaryAttestationInfo.diagnosticCopyText,
                        )
                    )
                }
                SupplementaryAttestationInfoAnomalyKind.MISMATCH -> {
                    add(
                        fact(
                            "Module hash",
                            "Attested MODULE_HASH did not match getSupplementaryAttestationInfo(MODULE_HASH).",
                            TeeSignalLevel.WARN,
                            hiddenCopyText = artifacts.supplementaryAttestationInfo.diagnosticCopyText,
                        )
                    )
                }
                SupplementaryAttestationInfoAnomalyKind.UNEXPECTED_ATTESTATION_MODULE_HASH -> {
                    add(
                        fact(
                            "Module hash",
                            "Attestation carried MODULE_HASH while getSupplementaryAttestationInfo(MODULE_HASH) was unavailable.",
                            TeeSignalLevel.WARN,
                            hiddenCopyText = artifacts.supplementaryAttestationInfo.diagnosticCopyText,
                        )
                    )
                }
                SupplementaryAttestationInfoAnomalyKind.NONE,
                SupplementaryAttestationInfoAnomalyKind.UNSUPPORTED -> Unit
            }
            if (
                artifacts.updateSubcomponentStaleResponsePersistence.anomalyKind ==
                UpdateSubcomponentStaleResponseAnomalyKind.STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE
            ) {
                add(
                    fact(
                        "Update persistence",
                        "UpdateSubcomponent stale TEE response persistence detected.",
                        TeeSignalLevel.FAIL,
                    )
                )
            }
            if (!artifacts.pairConsistency.keyMatchesCertificate) {
                add(
                    fact(
                        "Key pair",
                        "Leaf certificate key did not verify fresh local signatures.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.aesGcm.executed && !artifacts.aesGcm.roundTripSucceeded) {
                add(
                    fact(
                        "AES-GCM",
                        "AndroidKeyStore AES-GCM round-trip failed.",
                        TeeSignalLevel.FAIL,
                    )
                )
            }
            val aesGcmAuthorizationFailures = aesGcmAuthorizationFailures(artifacts.aesGcm)
            if (artifacts.aesGcm.executed && aesGcmAuthorizationFailures.isNotEmpty()) {
                add(
                    fact(
                        "AES-GCM",
                        "AndroidKeyStore AES-GCM accepted unauthorized parameters: ${aesGcmAuthorizationFailures.joinToString("; ")}.",
                        TeeSignalLevel.FAIL,
                    )
                )
            }
            if (artifacts.aesGcm.executed && artifacts.aesGcm.insideSecureHardware == false) {
                add(
                    fact(
                        "AES-GCM",
                        "AndroidKeyStore AES-GCM key was software-backed instead of secure hardware.",
                        TeeSignalLevel.WARN,
                    )
                )
            }
            val keyMintCryptoFailures = keyMintCryptoFailures(artifacts)
            if (keyMintCryptoFailures.isNotEmpty()) {
                add(
                    fact(
                        "KeyMint crypto",
                        "Hardware-backed KeyMint failed crypto capability checks: ${keyMintCryptoFailures.joinToString("; ")}.",
                        TeeSignalLevel.FAIL,
                    )
                )
            }
            if (!artifacts.lifecycle.deleteRemovedAlias || !artifacts.lifecycle.regeneratedFreshMaterial) {
                add(
                    fact(
                        "Lifecycle",
                        "Delete/regenerate behavior contradicted a clean keystore path.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (!artifacts.pureCertificate.pureCertificateReturnsNullKey) {
                add(
                    fact(
                        "Pure certificate",
                        "getKey() returned a key object for a certificate-only entry.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.pureCertificateSecurityLevel.executed &&
                artifacts.pureCertificateSecurityLevel.securityLevelPresent
            ) {
                add(
                    fact(
                        "Pure certificate",
                        "Certificate-only entry exposed Keystore2 security-level metadata.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.operationErrorPath.executed &&
                (!artifacts.operationErrorPath.createOperationSucceeded ||
                    !artifacts.operationErrorPath.updateAadServiceSpecific ||
                    !artifacts.operationErrorPath.oversizedUpdateRejected ||
                    !artifacts.operationErrorPath.abortInvalidatedHandle)
            ) {
                add(
                    fact(
                        "Operation path",
                        "Keystore2 operation error handling diverged from native-style semantics.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.biometricIntegration.executed &&
                artifacts.biometricIntegration.strongBiometricAvailable &&
                (!artifacts.biometricIntegration.keyCreated || !artifacts.biometricIntegration.keyRetrieved)
            ) {
                add(
                    fact(
                        "Biometric TEE",
                        "Strong biometric was available, but user-auth-bound key creation or retrieval failed.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.binderHookBootstrap.executed && !artifacts.binderHookBootstrap.hookInstalled) {
                add(
                    fact(
                        "Binder hook",
                        "Binder hook bootstrap did not complete successfully.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.binderPatchMode.executed &&
                artifacts.binderPatchMode.hookInstalled &&
                (artifacts.binderPatchMode.leafDiffers || artifacts.binderPatchMode.chainDiffers)
            ) {
                add(
                    fact(
                        "Patch mode",
                        "generateKey and getKeyEntry returned different certificate materials.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.binderChainConsistency.executed &&
                (
                    !artifacts.binderChainConsistency.hookInstalled ||
                        artifacts.binderChainConsistency.suspiciousLeafIssuerSpki ||
                        !artifacts.binderChainConsistency.activeProbeSecondCycleSucceeded ||
                        !artifacts.binderChainConsistency.deleteEntryRemovedAlias ||
                        (artifacts.binderChainConsistency.binderMaterialAvailable &&
                            !artifacts.binderChainConsistency.chainMatches) ||
                        (artifacts.binderChainConsistency.generateMaterialAvailable &&
                            artifacts.binderChainConsistency.binderMaterialAvailable &&
                            (
                                !artifacts.binderChainConsistency.generateVsGetKeyEntryLeafMatches ||
                                    !artifacts.binderChainConsistency.generateVsGetKeyEntryChainMatches
                                ))
                    )
            ) {
                add(
                    fact(
                        "Binder chain",
                        if (!artifacts.binderChainConsistency.hookInstalled) {
                            "Binder capture hook bootstrap failed."
                        } else {
                            "Java KeyStore, generateKey, and getKeyEntry certificate materials diverged."
                        },
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.updateSubcomponent.keyNotFoundStyleFailure || grantUpdateSubcomponentFailed(artifacts)) {
                add(
                    fact(
                        "Update path",
                        updateSubcomponentFailureSummary(artifacts),
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.native.leafDerPrimaryDetected) {
                add(
                    fact(
                        "TS leaf DER",
                        "Primary TrickyStore DER fingerprint matched locally.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.native.gotHookDetected) {
                add(
                    fact(
                        "TrickyStore ioctl",
                        "libbinder ioctl GOT entry differed from libc.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.native.inlineHookDetected) {
                add(
                    fact(
                        "TrickyStore ioctl",
                        "ioctl prologue looked patched or redirected.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.native.honeypotDetected) {
                add(
                    fact(
                        "TrickyStore ioctl",
                        "Keystore-style binder honeypot triggered abnormal ioctl timing.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            if (artifacts.native.trickyStoreDetected) {
                add(
                    fact(
                        "TrickyStore",
                        "Process-side indicators matched ${nativeMethodSummary(artifacts)}.",
                        TeeSignalLevel.FAIL
                    )
                )
            }
            artifacts.strongBox.hardFailures.forEach { message ->
                add(fact("StrongBox", message, TeeSignalLevel.WARN))
            }
        }
    }
}
