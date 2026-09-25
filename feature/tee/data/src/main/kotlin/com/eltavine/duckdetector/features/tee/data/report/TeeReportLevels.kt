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

import com.eltavine.duckdetector.capability.attestation.data.AttestationSnapshot
import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import com.eltavine.duckdetector.capability.attestation.domain.TeeTrustRoot
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2PostProcessingAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SupplementaryAttestationInfoAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentStaleResponseAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.VintfKeyMintVersionAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.rkp.RkpProvisionedManufacturerAnomalyKind
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceItem
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkMode
import com.eltavine.duckdetector.features.tee.domain.TeePatchGrade
import com.eltavine.duckdetector.features.tee.domain.TeePatchState
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel

internal fun aesGcmLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    return when {
        !artifacts.aesGcm.executed -> TeeSignalLevel.INFO
        !artifacts.aesGcm.roundTripSucceeded -> TeeSignalLevel.FAIL
        aesGcmAuthorizationFailures(artifacts.aesGcm).isNotEmpty() -> TeeSignalLevel.FAIL
        artifacts.aesGcm.insideSecureHardware == false -> TeeSignalLevel.WARN
        else -> TeeSignalLevel.PASS
    }
}

internal fun listEntriesConsistencyLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.listEntriesConsistency
    return when {
        !result.executed -> TeeSignalLevel.INFO
        result.badParcelableLikeCrash || result.inconsistent -> TeeSignalLevel.FAIL
        else -> TeeSignalLevel.PASS
    }
}

internal fun listEntriesBatchedLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.listEntriesBatched
    return when {
        !result.executed -> TeeSignalLevel.INFO
        result.cursorEchoed -> TeeSignalLevel.FAIL
        result.expectedNextMissing -> TeeSignalLevel.WARN
        else -> TeeSignalLevel.PASS
    }
}

internal fun keyMetadataSemanticsLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.keyMetadataSemantics
    return when {
        !result.executed -> TeeSignalLevel.INFO
        result.usesKeyIdDomain && result.aliasCleared -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.FAIL
    }
}

internal fun importKeyRetainedAttestationNarrativeLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.importKeyRetainedAttestationNarrative
    return when {
        !result.executed -> TeeSignalLevel.INFO
        result.retainedNarrativeDetected -> TeeSignalLevel.FAIL
        result.importSupported && result.markerImportBaselineClean -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.INFO
    }
}

internal fun grantDomainFullChainSplitLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.grantDomainFullChainSplit
    return when {
        // These anomaly kinds are already curated by the probe, so reducer can safely upgrade them without parsing detail text.
        // 这些 anomaly kind 已由 probe 结构化归类，reducer 不需要解析 detail 文本即可升级。
        result.anomalyKind == GrantDomainAnomalyKind.ISOLATED_CHAIN_SPLIT -> TeeSignalLevel.FAIL
        result.anomalyKind == GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN ->
            TeeSignalLevel.FAIL
        result.anomalyKind == GrantDomainAnomalyKind.ISOLATED_PRIVATE_READBACK_CRASH -> TeeSignalLevel.WARN

        result.executed && result.splitDetected -> TeeSignalLevel.FAIL
        result.executed && result.available -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.INFO
    }
}

internal fun syntheticGrantGranteeBlindReadbackLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.syntheticGrantGranteeBlindReadback
    return when (result.anomalyKind) {
        SyntheticGrantGranteeBlindReadbackAnomalyKind.NON_GRANTEE_READBACK_ALLOWED -> TeeSignalLevel.FAIL
        SyntheticGrantGranteeBlindReadbackAnomalyKind.NONE ->
            if (result.executed && result.available) TeeSignalLevel.PASS else TeeSignalLevel.INFO
        SyntheticGrantGranteeBlindReadbackAnomalyKind.SKIPPED_AFTER_EXISTING_GRANT_DANGER,
        SyntheticGrantGranteeBlindReadbackAnomalyKind.UNAVAILABLE -> TeeSignalLevel.INFO
    }
}

internal fun syntheticGrantGetKeyEntryAccessVectorBlindnessLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.syntheticGrantGetKeyEntryAccessVectorBlindness
    return when (result.anomalyKind) {
        SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.GET_KEY_ENTRY_WITHOUT_GET_INFO_ALLOWED ->
            TeeSignalLevel.FAIL
        SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.NONE ->
            if (result.executed && result.available) TeeSignalLevel.PASS else TeeSignalLevel.INFO
        SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.SKIPPED_AFTER_EXISTING_GRANT_DANGER,
        SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.UNAVAILABLE -> TeeSignalLevel.INFO
    }
}

internal fun grantSelfDomainFullChainSplitLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.grantSelfDomainFullChainSplit
    return when {
        // Same-UID key-not-found is not ordinary unavailability: the owner alias was proven readable before grant.
        // 同 UID key-not-found 不是普通不可用：grant 之前 owner alias 已被证明可读。
        result.anomalyKind == GrantSelfDomainAnomalyKind.SELF_CHAIN_SPLIT ||
            result.anomalyKind == GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN ||
            result.anomalyKind == GrantSelfDomainAnomalyKind.SELF_GRANT_ATTESTATION_APP_KEY_NOT_FOUND -> {
            TeeSignalLevel.FAIL
        }
        result.executed && result.available -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.INFO
    }
}

internal fun updateSubcomponentStaleResponsePersistenceLevel(
    artifacts: TeeScanArtifacts,
): TeeSignalLevel {
    val result = artifacts.updateSubcomponentStaleResponsePersistence
    return when (result.anomalyKind) {
        UpdateSubcomponentStaleResponseAnomalyKind.STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE ->
            TeeSignalLevel.FAIL

        UpdateSubcomponentStaleResponseAnomalyKind.NONE -> TeeSignalLevel.PASS
        UpdateSubcomponentStaleResponseAnomalyKind.UPDATE_SUBCOMPONENT_UNOBSERVABLE,
        UpdateSubcomponentStaleResponseAnomalyKind.UPDATE_FAILED,
        UpdateSubcomponentStaleResponseAnomalyKind.UNAVAILABLE -> TeeSignalLevel.INFO
    }
}

internal fun keyMetadataShapeLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.keyMetadataShape
    return when {
        !result.executed -> TeeSignalLevel.INFO
        result.modificationTimeValid && result.hasOriginTag -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.FAIL
    }
}

internal fun pureCertificateTopLevelSecurityLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.pureCertificateSecurityLevel
    return when {
        !result.executed -> TeeSignalLevel.INFO
        result.securityLevelPresent -> TeeSignalLevel.FAIL
        else -> TeeSignalLevel.PASS
    }
}

internal fun pureCertificateMetadataSecurityLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.pureCertificateSecurityLevel
    return when {
        !result.executed -> TeeSignalLevel.INFO
        result.metadataSecurityLevelPresent -> TeeSignalLevel.INFO
        else -> TeeSignalLevel.PASS
    }
}

internal fun operationErrorPathLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.operationErrorPath
    return when {
        !result.executed -> TeeSignalLevel.INFO
        !result.createOperationSucceeded ||
            !result.updateAadServiceSpecific ||
            !result.oversizedUpdateRejected ||
            !result.abortInvalidatedHandle -> TeeSignalLevel.FAIL
        result.fallbackCompatParamsUsed -> TeeSignalLevel.WARN

        else -> TeeSignalLevel.PASS
    }
}

internal fun biometricIntegrationLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.biometricIntegration
    return when {
        !result.executed -> TeeSignalLevel.INFO
        !result.strongBiometricAvailable -> TeeSignalLevel.INFO
        result.keyCreated && result.keyRetrieved -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.FAIL
    }
}

internal fun binderChainConsistencyLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.binderChainConsistency
    return when {
        !result.executed -> TeeSignalLevel.INFO
        !result.hookInstalled -> TeeSignalLevel.FAIL
        result.suspiciousLeafIssuerSpki -> TeeSignalLevel.FAIL
        !result.activeProbeSecondCycleSucceeded -> TeeSignalLevel.FAIL
        !result.deleteEntryRemovedAlias -> TeeSignalLevel.FAIL
        !result.keystoreChainAvailable || !result.binderMaterialAvailable -> TeeSignalLevel.INFO
        !result.generateVsGetKeyEntryLeafMatches || !result.generateVsGetKeyEntryChainMatches -> TeeSignalLevel.FAIL
        result.chainMatches -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.FAIL
    }
}

internal fun binderHookBootstrapLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.binderHookBootstrap
    return when {
        !result.executed -> TeeSignalLevel.INFO
        result.hookInstalled -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.FAIL
    }
}

internal fun legacyKeystorePathLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.legacyKeystorePath
    return when {
        !result.executed -> TeeSignalLevel.INFO
        !result.hookInstalled -> TeeSignalLevel.INFO
        !result.legacyMaterialAvailable -> TeeSignalLevel.INFO
        result.chainMatches -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.WARN
    }
}

internal fun binderPatchModeLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val result = artifacts.binderPatchMode
    return when {
        !result.executed -> TeeSignalLevel.INFO
        !result.hookInstalled -> TeeSignalLevel.FAIL
        result.leafDiffers || result.chainDiffers -> TeeSignalLevel.FAIL
        result.generateMaterialAvailable && result.keyEntryMaterialAvailable -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.INFO
    }
}

internal fun chainLayoutLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    artifacts.chainStructure.provisioningConsistencyIssue -> TeeSignalLevel.WARN
    else -> TeeSignalLevel.INFO
}

internal fun challengeLevel(snapshot: AttestationSnapshot): TeeSignalLevel = when {
    snapshot.trustedAttestationIndex == null -> TeeSignalLevel.INFO
    snapshot.challengeVerified -> TeeSignalLevel.PASS
    else -> TeeSignalLevel.FAIL
}

internal fun verifiedBootLevel(snapshot: AttestationSnapshot): TeeSignalLevel {
    val bootState = snapshot.rootOfTrust?.verifiedBootState ?: return TeeSignalLevel.INFO
    return if (bootState == "Verified") TeeSignalLevel.PASS else TeeSignalLevel.WARN
}

internal fun bootSignalLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val root = artifacts.snapshot.rootOfTrust
    return when {
        artifacts.bootConsistency.hasHardAnomaly -> TeeSignalLevel.FAIL
        root == null -> TeeSignalLevel.INFO
        !artifacts.bootConsistency.runtimePropsAvailable -> TeeSignalLevel.INFO
        artifacts.bootConsistency.runtimeComparisonPerformed -> TeeSignalLevel.PASS
        else -> TeeSignalLevel.INFO
    }
}

internal fun deviceInfoLevel(snapshot: AttestationSnapshot): TeeSignalLevel {
    return if (snapshot.deviceInfo.asDisplayMap()
            .isEmpty()
    ) TeeSignalLevel.INFO else TeeSignalLevel.PASS
}

internal fun trustLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    !artifacts.trust.chainSignatureValid -> TeeSignalLevel.FAIL
    hasLocalTrustReviewSignals(artifacts) -> TeeSignalLevel.WARN
    normalizeTrustRoot(artifacts.trust.trustRoot) == TeeTrustRoot.GOOGLE -> TeeSignalLevel.PASS
    normalizeTrustRoot(artifacts.trust.trustRoot) == TeeTrustRoot.AOSP -> TeeSignalLevel.WARN
    else -> TeeSignalLevel.INFO
}

internal fun rkpDisplayLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    artifacts.rkp.provisioned && !artifacts.trust.chainSignatureValid -> TeeSignalLevel.FAIL
    artifacts.rkp.provisioned && hasLocalTrustReviewSignals(artifacts) -> TeeSignalLevel.WARN
    artifacts.rkp.provisioned -> TeeSignalLevel.PASS
    artifacts.rkp.consistencyIssue != null -> TeeSignalLevel.WARN
    else -> TeeSignalLevel.INFO
}

internal fun crlSignalLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    hasHardRevocation(artifacts) -> TeeSignalLevel.FAIL
    hasLocalMassAbuseRevocation(artifacts) -> TeeSignalLevel.WARN
    artifacts.crl.networkState.mode == TeeNetworkMode.ACTIVE -> TeeSignalLevel.PASS
    artifacts.crl.networkState.mode == TeeNetworkMode.ERROR -> TeeSignalLevel.WARN
    else -> TeeSignalLevel.INFO
}

internal fun tierLevel(tier: TeeTier): TeeSignalLevel = when (tier) {
    TeeTier.STRONGBOX, TeeTier.TEE -> TeeSignalLevel.PASS
    TeeTier.SOFTWARE -> TeeSignalLevel.WARN
    TeeTier.NONE -> TeeSignalLevel.FAIL
    TeeTier.UNKNOWN -> TeeSignalLevel.INFO
}

private fun patchLevel(patchState: TeePatchState): TeeSignalLevel = when (patchState.grade) {
    TeePatchGrade.MATCHED -> TeeSignalLevel.PASS
    TeePatchGrade.WARNING, TeePatchGrade.SUSPICIOUS -> TeeSignalLevel.WARN
    TeePatchGrade.UNKNOWN -> TeeSignalLevel.INFO
}

internal fun lifecycleLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    artifacts.lifecycle.deleteRemovedAlias && artifacts.lifecycle.regeneratedFreshMaterial -> TeeSignalLevel.PASS
    else -> TeeSignalLevel.FAIL
}

internal fun keyboxLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    !artifacts.keyboxImport.executed -> TeeSignalLevel.INFO
    artifacts.keyboxImport.markerPreserved -> TeeSignalLevel.PASS
    else -> TeeSignalLevel.FAIL
}

internal fun oversizedChallengeLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    artifacts.oversizedChallenge.acceptedOversizedChallenge -> TeeSignalLevel.WARN
    else -> TeeSignalLevel.PASS
}

internal fun generateModeAnomalyLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when (
    generateModeAnomalyState(artifacts)
) {
    GenerateModeAnomalyState.MATCHED -> TeeSignalLevel.FAIL
    GenerateModeAnomalyState.CLEAN -> TeeSignalLevel.PASS
    GenerateModeAnomalyState.UNAVAILABLE -> TeeSignalLevel.INFO
}

internal fun timingSideChannelLevel(artifacts: TeeScanArtifacts): TeeSignalLevel {
    val skipSignature = timingSideChannelSkipSignature(artifacts.timingSideChannel)
    return when {
        skipSignature != null -> skipSignature.level
        !artifacts.timingSideChannel.probeRan -> TeeSignalLevel.INFO
        !artifacts.timingSideChannel.measurementAvailable -> TeeSignalLevel.INFO
        !artifacts.timingSideChannel.ratioEligible -> TeeSignalLevel.INFO
        artifacts.timingSideChannel.suspicious -> TeeSignalLevel.WARN
        else -> TeeSignalLevel.INFO
    }
}

internal fun strongBoxLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    artifacts.strongBox.hardFailures.isNotEmpty() -> TeeSignalLevel.WARN
    artifacts.strongBox.warnings.isNotEmpty() -> TeeSignalLevel.INFO
    artifacts.strongBox.available -> TeeSignalLevel.PASS
    else -> TeeSignalLevel.INFO
}

internal fun soterLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    artifacts.soter.damaged -> TeeSignalLevel.FAIL
    artifacts.soter.available -> TeeSignalLevel.PASS
    artifacts.soter.abnormalEnvironment -> TeeSignalLevel.WARN
    !artifacts.soter.serviceReachable -> TeeSignalLevel.WARN
    else -> TeeSignalLevel.INFO
}

internal fun supplementaryAttestationInfoLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when (
    artifacts.supplementaryAttestationInfo.anomalyKind
) {
    SupplementaryAttestationInfoAnomalyKind.MISSING_ATTESTATION_MODULE_HASH,
    SupplementaryAttestationInfoAnomalyKind.MISMATCH,
    SupplementaryAttestationInfoAnomalyKind.UNEXPECTED_ATTESTATION_MODULE_HASH -> TeeSignalLevel.WARN
    SupplementaryAttestationInfoAnomalyKind.NONE -> TeeSignalLevel.PASS
    SupplementaryAttestationInfoAnomalyKind.UNSUPPORTED -> TeeSignalLevel.INFO
}

internal fun vintfKeyMintVersionLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when (
    artifacts.vintfKeyMintVersion.anomalyKind
) {
    VintfKeyMintVersionAnomalyKind.MISMATCH -> TeeSignalLevel.FAIL
    VintfKeyMintVersionAnomalyKind.NONE -> TeeSignalLevel.PASS
    VintfKeyMintVersionAnomalyKind.UNREADABLE,
    VintfKeyMintVersionAnomalyKind.NO_DECLARATION,
    VintfKeyMintVersionAnomalyKind.NO_ATTESTED_VERSION -> TeeSignalLevel.INFO
}

internal fun postProcessingLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when (
    artifacts.postProcessing.anomalyKind
) {
    Keystore2PostProcessingAnomalyKind.ROOT_OF_TRUST_DIVERGENCE,
    Keystore2PostProcessingAnomalyKind.TIMING_DETECTED -> TeeSignalLevel.FAIL
    Keystore2PostProcessingAnomalyKind.TIMING_SUSPECT -> TeeSignalLevel.WARN
    Keystore2PostProcessingAnomalyKind.NONE -> TeeSignalLevel.PASS
    // 这三种都是"测不了"，不能当成通过 / These three all mean "could not test" and must not read as a pass
    Keystore2PostProcessingAnomalyKind.RKP_UNAVAILABLE,
    Keystore2PostProcessingAnomalyKind.RKP_FALLBACK_INCONCLUSIVE,
    Keystore2PostProcessingAnomalyKind.UNMEASURABLE -> TeeSignalLevel.INFO
}

internal fun rkpProvisionedManufacturerLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when (
    artifacts.rkpProvisionedManufacturer.anomalyKind
) {
    RkpProvisionedManufacturerAnomalyKind.MISMATCH -> TeeSignalLevel.FAIL
    RkpProvisionedManufacturerAnomalyKind.NONE -> TeeSignalLevel.PASS
    RkpProvisionedManufacturerAnomalyKind.DISMISSED_NO_PROVISIONING_MANUFACTURER,
    RkpProvisionedManufacturerAnomalyKind.DISMISSED_NO_ATTESTED_MANUFACTURER -> TeeSignalLevel.INFO
}

internal fun indicatorLevel(
    policyHardIndicators: List<TeeEvidenceItem>,
    policySoftIndicators: List<TeeEvidenceItem>,
    supplementaryIndicators: List<TeeEvidenceItem>,
): TeeSignalLevel = when {
    policyHardIndicators.isNotEmpty() -> TeeSignalLevel.FAIL
    supplementaryIndicators.any { it.level == TeeSignalLevel.FAIL } -> TeeSignalLevel.FAIL
    policySoftIndicators.isNotEmpty() ||
        supplementaryIndicators.any { it.level == TeeSignalLevel.WARN } -> TeeSignalLevel.WARN
    else -> TeeSignalLevel.PASS
}

internal fun supplementaryReviewLevel(indicators: List<TeeEvidenceItem>): TeeSignalLevel = when {
    // Report aggregation is severity-first: a later FAIL must still outrank an earlier WARN.
    // Report 聚合按严重级别优先：后出现的 FAIL 必须压过先出现的 WARN。
    indicators.any { it.level == TeeSignalLevel.FAIL } -> TeeSignalLevel.FAIL
    indicators.any { it.level == TeeSignalLevel.WARN } -> TeeSignalLevel.WARN
    else -> TeeSignalLevel.INFO
}

internal fun localTrustChainLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    artifacts.trust.chainLength == 0 -> TeeSignalLevel.INFO
    !artifacts.trust.chainSignatureValid -> TeeSignalLevel.FAIL
    hasLocalTrustReviewSignals(artifacts) -> TeeSignalLevel.WARN
    else -> TeeSignalLevel.PASS
}
