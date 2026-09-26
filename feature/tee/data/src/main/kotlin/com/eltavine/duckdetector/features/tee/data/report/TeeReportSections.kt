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
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceSection
import com.eltavine.duckdetector.features.tee.domain.TeePatchState
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel

internal fun buildSections(
    artifacts: TeeScanArtifacts,
    patchState: TeePatchState,
    policyHardIndicators: List<TeeEvidenceItem>,
    policySoftIndicators: List<TeeEvidenceItem>,
    supplementaryIndicators: List<TeeEvidenceItem>,
): List<TeeEvidenceSection> {
    return listOf(
        TeeEvidenceSection(
            title = "Trust",
            items = buildList {
                add(
                    fact(
                        "Local chain",
                        if (artifacts.trust.chainSignatureValid) "Verified" else "Failed",
                        if (artifacts.trust.chainSignatureValid) TeeSignalLevel.PASS else TeeSignalLevel.FAIL
                    )
                )
                add(
                    fact(
                        "Trust root",
                        trustRootLabel(artifacts.trust.trustRoot),
                        trustLevel(artifacts)
                    )
                )
                add(
                    fact(
                        "Chain layout",
                        chainLayoutValue(artifacts),
                        chainLayoutLevel(artifacts)
                    )
                )
                add(fact("RKP", rkpValue(artifacts), rkpDisplayLevel(artifacts)))
                add(fact("CRL", crlValue(artifacts), crlSignalLevel(artifacts)))
                add(
                    fact(
                        "Root fingerprint",
                        shortFingerprint(artifacts.trust.rootFingerprint),
                        TeeSignalLevel.INFO
                    )
                )
            },
        ),
        TeeEvidenceSection(
            title = "Attestation",
            items = buildList {
                add(
                    fact(
                        "Tier",
                        tierValue(artifacts),
                        tierLevel(effectiveTier(artifacts))
                    )
                )
                add(fact("Versions", versionsValue(artifacts.snapshot), TeeSignalLevel.INFO))
                add(
                    fact(
                        "Challenge",
                        challengeValue(artifacts.snapshot),
                        challengeLevel(artifacts.snapshot)
                    )
                )
                add(
                    fact(
                        "Verified boot",
                        verifiedBootValue(artifacts.snapshot),
                        verifiedBootLevel(artifacts.snapshot)
                    )
                )
                add(
                    fact(
                        "Boot consistency",
                        bootConsistencyValue(artifacts),
                        bootSignalLevel(artifacts)
                    )
                )
                add(
                    fact(
                        "Device IDs",
                        deviceInfoValue(artifacts.snapshot),
                        deviceInfoLevel(artifacts.snapshot)
                    )
                )
                add(
                    fact(
                        "Key properties",
                        keyPropertiesValue(artifacts.snapshot),
                        TeeSignalLevel.INFO
                    )
                )
                add(fact("User auth", authStateValue(artifacts.snapshot), TeeSignalLevel.INFO))
                add(
                    fact(
                        "Application",
                        applicationInfoValue(artifacts.snapshot),
                        TeeSignalLevel.INFO
                    )
                )
            },
        ),
        TeeEvidenceSection(
            title = "Checks",
            items = buildList {
                add(
                    fact(
                        "Indicators",
                        indicatorValue(
                            policyHardIndicators = policyHardIndicators,
                            policySoftIndicators = policySoftIndicators,
                            supplementaryIndicators = supplementaryIndicators,
                        ),
                        indicatorLevel(
                            policyHardIndicators = policyHardIndicators,
                            policySoftIndicators = policySoftIndicators,
                            supplementaryIndicators = supplementaryIndicators,
                        ),
                    )
                )
                add(
                    fact(
                        "Key pair",
                        keyPairValue(artifacts),
                        keyPairLevel(artifacts),
                    )
                )
                add(
                    fact(
                        "AES-GCM",
                        aesGcmValue(artifacts),
                        aesGcmLevel(artifacts)
                    )
                )
                add(fact("Lifecycle", lifecycleValue(artifacts), lifecycleLevel(artifacts)))
                add(
                    fact(
                        "KeyMint crypto",
                        keyMintCryptoValue(artifacts),
                        keyMintCryptoLevel(artifacts),
                        hiddenCopyText = keyMintCryptoDiagnosticCopyText(artifacts),
                    )
                )
                add(
                    fact(
                        "Timing",
                        timingValue(artifacts),
                        if (artifacts.timing.suspicious) TeeSignalLevel.WARN else TeeSignalLevel.INFO
                    )
                )
                add(
                    fact(
                        "Timing side-channel",
                        timingSideChannelValue(artifacts),
                        timingSideChannelLevel(artifacts),
                        hiddenCopyText = artifacts.timingSideChannel.stackCopyPayload,
                    )
                )
                add(
                    fact(
                        "Oversized challenge",
                        oversizedChallengeValue(artifacts),
                        oversizedChallengeLevel(artifacts)
                    )
                )
                add(
                    fact(
                        "TEE Simulator generate-mode fingerprint",
                        generateModeAnomalyValue(artifacts),
                        generateModeAnomalyLevel(artifacts),
                        hiddenCopyText = artifacts.generateModeParcelFingerprint.diagnosticCopyText,
                    )
                )
                add(fact("Keybox", keyboxValue(artifacts), keyboxLevel(artifacts)))
                add(
                    fact(
                        "ImportKey narrative",
                        importKeyRetainedAttestationNarrativeValue(artifacts),
                        importKeyRetainedAttestationNarrativeLevel(artifacts)
                    )
                )
                add(
                    fact(
                        if (keyMintRuntimeIdentityMismatch(artifacts)) {
                            "KeyMint runtime identity"
                        } else {
                            "KeyMint VINTF"
                        },
                        vintfKeyMintVersionValue(artifacts),
                        vintfKeyMintVersionLevel(artifacts),
                        hiddenCopyText = artifacts.vintfKeyMintVersion.diagnosticCopyText,
                    )
                )
                add(
                    fact(
                        "Cert post-processing",
                        postProcessingValue(artifacts),
                        postProcessingLevel(artifacts),
                    )
                )
                add(
                    fact(
                        "RKP manufacturer",
                        rkpProvisionedManufacturerValue(artifacts),
                        rkpProvisionedManufacturerLevel(artifacts),
                    )
                )
                add(
                    fact(
                        "Module hash",
                        supplementaryAttestationInfoValue(artifacts),
                        supplementaryAttestationInfoLevel(artifacts),
                        hiddenCopyText = artifacts.supplementaryAttestationInfo.diagnosticCopyText,
                    )
                )
                add(
                    fact(
                        "Grant isolated-domain",
                        grantDomainFullChainSplitValue(artifacts),
                        grantDomainFullChainSplitLevel(artifacts),
                        hiddenCopyText = artifacts.grantDomainFullChainSplit.diagnosticCopyText
                            .takeIf { it.isNotBlank() },
                        grant = isolatedDomainGrantEvidence(artifacts),
                    )
                )
                add(
                    fact(
                        "Grant caller binding",
                        syntheticGrantGranteeBlindReadbackValue(artifacts),
                        syntheticGrantGranteeBlindReadbackLevel(artifacts),
                        hiddenCopyText = artifacts.syntheticGrantGranteeBlindReadback.diagnosticCopyText
                            .takeIf { it.isNotBlank() },
                        grant = callerBindingGrantEvidence(artifacts),
                    )
                )
                add(
                    fact(
                        "Grant access vector",
                        syntheticGrantGetKeyEntryAccessVectorBlindnessValue(artifacts),
                        syntheticGrantGetKeyEntryAccessVectorBlindnessLevel(artifacts),
                        hiddenCopyText = artifacts.syntheticGrantGetKeyEntryAccessVectorBlindness.diagnosticCopyText
                            .takeIf { it.isNotBlank() },
                    )
                )
                add(
                    fact(
                        "Grant self-domain",
                        grantSelfDomainFullChainSplitValue(artifacts),
                        grantSelfDomainFullChainSplitLevel(artifacts),
                        hiddenCopyText = artifacts.grantSelfDomainFullChainSplit.diagnosticCopyText
                            .takeIf { it.isNotBlank() },
                        grant = selfDomainGrantEvidence(artifacts),
                    )
                )
                add(
                    fact(
                        "Keystore2",
                        keystore2Value(artifacts),
                        if (artifacts.keystore2Hook.javaHookDetected) TeeSignalLevel.FAIL else TeeSignalLevel.INFO
                    )
                )
                add(
                    fact(
                        "Legacy keystore",
                        legacyKeystorePathValue(artifacts),
                        legacyKeystorePathLevel(artifacts)
                    )
                )
                add(
                    fact(
                        "listEntries",
                        listEntriesConsistencyValue(artifacts),
                        listEntriesConsistencyLevel(artifacts)
                    )
                )
                add(
                    fact(
                        "listEntriesBatched",
                        listEntriesBatchedValue(artifacts),
                        listEntriesBatchedLevel(artifacts)
                    )
                )
                add(
                    fact(
                        "Metadata key",
                        keyMetadataSemanticsValue(artifacts),
                        keyMetadataSemanticsLevel(artifacts)
                    )
                )
                add(
                    fact(
                        "Metadata shape",
                        keyMetadataShapeValue(artifacts),
                        keyMetadataShapeLevel(artifacts)
                    )
                )
                add(
                    fact(
                        "Pure cert",
                        pureCertificateValue(artifacts),
                        pureCertificateLevel(artifacts),
                    )
                )
                add(
                    fact(
                        "Pure cert level",
                        pureCertificateTopLevelSecurityValue(artifacts),
                        pureCertificateTopLevelSecurityLevel(artifacts)
                    )
                )
                add(
                    fact(
                        "Pure cert metadata",
                        pureCertificateMetadataSecurityValue(artifacts),
                        pureCertificateMetadataSecurityLevel(artifacts)
                    )
                )
                add(
                    fact(
                        "Operation path",
                        operationErrorPathValue(artifacts),
                        operationErrorPathLevel(artifacts)
                    )
                )
                add(
                    fact(
                        "Biometric TEE",
                        biometricIntegrationValue(artifacts),
                        biometricIntegrationLevel(artifacts)
                    )
                )
                add(
                    fact(
                        "Binder hook",
                        binderHookBootstrapValue(artifacts),
                        binderHookBootstrapLevel(artifacts)
                    )
                )
                add(
                    fact(
                        "Patch mode",
                        binderPatchModeValue(artifacts),
                        binderPatchModeLevel(artifacts)
                    )
                )
                add(
                    fact(
                        "Binder chain",
                        binderChainConsistencyValue(artifacts),
                        binderChainConsistencyLevel(artifacts)
                    )
                )
                add(
                    fact(
                        "Update path",
                        updateSubcomponentValue(artifacts),
                        updateSubcomponentLevel(artifacts)
                    )
                )
                add(
                    fact(
                        "Update persistence",
                        updateSubcomponentStaleResponsePersistenceValue(artifacts),
                        updateSubcomponentStaleResponsePersistenceLevel(artifacts)
                    )
                )
                add(
                    fact(
                        "Pruning",
                        pruningValue(artifacts),
                        TeeSignalLevel.INFO
                    )
                )
                add(
                    fact(
                        "Dual algorithm",
                        dualAlgorithmValue(artifacts),
                        TeeSignalLevel.INFO
                    )
                )
                add(
                    fact(
                        "ID attestation",
                        idAttestationValue(artifacts),
                        if (artifacts.idAttestation.mismatches.isNotEmpty()) TeeSignalLevel.WARN else TeeSignalLevel.INFO
                    )
                )
                add(fact("StrongBox", strongBoxValue(artifacts), strongBoxLevel(artifacts)))
                add(fact("Native", nativeValue(artifacts), nativeSignalLevel(artifacts)))
                add(fact("Soter", artifacts.soter.summary, soterLevel(artifacts)))
            },
        ),
    )
}
