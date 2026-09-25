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

package com.eltavine.duckdetector.features.tee.data.repository

import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainFullChainSplitResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainFullChainSplitResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeProbe

internal data class DeferredChecks(
    val pairConsistency: com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyPairConsistencyResult,
    val aesGcm: com.eltavine.duckdetector.features.tee.data.verification.keystore.AesGcmRoundTripResult,
    val lifecycle: com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyLifecycleResult,
    val keyMintCapability: com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMintCapabilityResult,
    val timing: com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingAnomalyResult,
    val timingSideChannel: com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingSideChannelResult,
    val oversizedChallenge: com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeResult,
    val keyboxImport: com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportResult,
    val importKeyRetainedAttestationNarrative: com.eltavine.duckdetector.features.tee.data.verification.keystore.ImportKeyRetainedAttestationNarrativeResult,
    val keystore2Hook: com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2HookResult,
    val generateModeParcelFingerprint: com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GenerateModeParcelFingerprintResult,
    val grantDomainFullChainSplit: com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainFullChainSplitResult,
    val syntheticGrantGranteeBlindReadback: com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackResult,
    val syntheticGrantGetKeyEntryAccessVectorBlindness: com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGetKeyEntryAccessVectorBlindnessResult,
    val grantSelfDomainFullChainSplit: com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainFullChainSplitResult,
    val legacyKeystorePath: com.eltavine.duckdetector.features.tee.data.verification.keystore.LegacyKeystorePathResult,
    val listEntriesConsistency: com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesConsistencyResult,
    val listEntriesBatched: com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesBatchedResult,
    val keyMetadataSemantics: com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataSemanticsResult,
    val keyMetadataShape: com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataShapeResult,
    val pureCertificate: com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateResult,
    val pureCertificateSecurityLevel: com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateSecurityLevelResult,
    val operationErrorPath: com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationErrorPathResult,
    val biometricIntegration: com.eltavine.duckdetector.features.tee.data.verification.keystore.BiometricTeeIntegrationResult,
    val binderHookBootstrap: com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderHookBootstrapResult,
    val binderPatchMode: com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderPatchModeResult,
    val binderChainConsistency: com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderChainConsistencyResult,
    val updateSubcomponent: com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentResult,
    val updateSubcomponentStaleResponsePersistence: com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentStaleResponsePersistenceResult,
    val pruning: com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationPruningResult,
    val dualAlgorithm: com.eltavine.duckdetector.features.tee.data.verification.certificate.DualAlgorithmChainResult,
    val idAttestation: com.eltavine.duckdetector.features.tee.data.verification.keystore.IdAttestationResult,
    val strongBox: com.eltavine.duckdetector.features.tee.data.verification.strongbox.StrongBoxBehaviorResult,
) {
    companion object {
        fun skipped(
            snapshot: com.eltavine.duckdetector.capability.attestation.data.AttestationSnapshot,
            timingSideChannel: com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingSideChannelResult,
        ) = DeferredChecks(
            pairConsistency = com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyPairConsistencyResult(
                keyMatchesCertificate = true,
                detail = "Deep checks were skipped because hardware-backed attestation was not established.",
            ),
            aesGcm = com.eltavine.duckdetector.features.tee.data.verification.keystore.AesGcmRoundTripResult(
                executed = false,
                detail = "AES-GCM round-trip probe skipped.",
            ),
            lifecycle = com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyLifecycleResult(
                created = false,
                deleteRemovedAlias = true,
                regeneratedFreshMaterial = true,
                detail = "Lifecycle probe skipped.",
            ),
            keyMintCapability = com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMintCapabilityResult(
                executed = false,
            ),
            timing = com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingAnomalyResult(
                suspicious = false,
                detail = "Timing probe skipped.",
            ),
            timingSideChannel = timingSideChannel,

            oversizedChallenge = com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeResult(
                acceptedOversizedChallenge = false,
                acceptedSizes = emptyList(),
                attemptedSizes = com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeProbe.CHALLENGE_SIZES,
                detail = "Oversized challenge probe skipped.",
            ),
            keyboxImport = com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportResult(
                executed = false,
                markerPreserved = true,
                marker = com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportProbe.FIXTURE_MARKER,
                detail = "Keybox import probe skipped.",
            ),
            importKeyRetainedAttestationNarrative = com.eltavine.duckdetector.features.tee.data.verification.keystore.ImportKeyRetainedAttestationNarrativeResult(
                executed = false,
                detail = "ImportKey retained attestation narrative probe skipped.",
            ),
            keystore2Hook = com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2HookResult(
                available = false,
                detail = "Keystore2 hook probe skipped.",
            ),
            generateModeParcelFingerprint = com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GenerateModeParcelFingerprintResult(
                executed = false,
                detail = "Keystore2 generate-mode parcel fingerprint probe skipped.",
            ),
            grantDomainFullChainSplit = com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainFullChainSplitResult(
                detail = "Grant-domain full-chain split probe skipped.",
            ),
            syntheticGrantGranteeBlindReadback = com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackResult(
                detail = "Grant caller-binding private binder probe skipped.",
            ),
            syntheticGrantGetKeyEntryAccessVectorBlindness =
                com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
                    detail = "Grant access-vector private binder probe skipped.",
                ),
            grantSelfDomainFullChainSplit = com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainFullChainSplitResult(
                detail = "Grant self-domain full-chain split probe skipped.",
            ),
            legacyKeystorePath = com.eltavine.duckdetector.features.tee.data.verification.keystore.LegacyKeystorePathResult(
                executed = false,
                detail = "Legacy keystore path probe skipped.",
            ),
            listEntriesConsistency = com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesConsistencyResult(
                executed = false,
                detail = "listEntries consistency probe skipped.",
            ),
            listEntriesBatched = com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesBatchedResult(
                executed = false,
                detail = "listEntriesBatched probe skipped.",
            ),
            keyMetadataSemantics = com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataSemanticsResult(
                executed = false,
                detail = "KeyMetadata semantics probe skipped.",
            ),
            keyMetadataShape = com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataShapeResult(
                executed = false,
                detail = "KeyMetadata shape probe skipped.",
            ),
            pureCertificate = com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateResult(
                pureCertificateReturnsNullKey = true,
                detail = "Pure certificate probe skipped.",
            ),
            pureCertificateSecurityLevel = com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateSecurityLevelResult(
                executed = false,
                detail = "Pure certificate security-level probe skipped.",
            ),
            operationErrorPath = com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationErrorPathResult(
                executed = false,
                detail = "Operation error-path probe skipped.",
            ),
            biometricIntegration = com.eltavine.duckdetector.features.tee.data.verification.keystore.BiometricTeeIntegrationResult(
                executed = false,
                detail = "Biometric TEE integration probe skipped.",
            ),
            binderHookBootstrap = com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderHookBootstrapResult(
                executed = false,
                detail = "Binder hook bootstrap probe skipped.",
            ),
            binderPatchMode = com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderPatchModeResult(
                executed = false,
                detail = "Binder patch-mode probe skipped.",
            ),
            binderChainConsistency = com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderChainConsistencyResult(
                executed = false,
                detail = "Binder chain consistency probe skipped.",
            ),
            updateSubcomponent = com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentResult(
                updateSucceeded = true,
                keyNotFoundStyleFailure = false,
                detail = "Update subcomponent probe skipped.",
            ),
            updateSubcomponentStaleResponsePersistence =
                com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentStaleResponsePersistenceResult(
                    detail = "UpdateSubcomponent stale response persistence probe skipped.",
                ),
            pruning = com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationPruningResult(
                suspicious = false,
                operationsCreated = 0,
                invalidatedOperations = 0,
                detail = "Pruning probe skipped.",
            ),
            dualAlgorithm = com.eltavine.duckdetector.features.tee.data.verification.certificate.DualAlgorithmChainResult(
                mismatchDetected = false,
                detail = "Dual algorithm comparison skipped.",
            ),
            idAttestation = com.eltavine.duckdetector.features.tee.data.verification.keystore.IdAttestationResult(
                mismatches = emptyList(),
                unavailableFields = emptyList(),
                detail = "ID attestation probe skipped.",
                probeRan = false,
            ),
            strongBox = com.eltavine.duckdetector.features.tee.data.verification.strongbox.StrongBoxBehaviorResult(
                requested = false,
                advertised = false,
                available = false,
                detail = "StrongBox probe skipped.",
            ),
        )
    }
}
