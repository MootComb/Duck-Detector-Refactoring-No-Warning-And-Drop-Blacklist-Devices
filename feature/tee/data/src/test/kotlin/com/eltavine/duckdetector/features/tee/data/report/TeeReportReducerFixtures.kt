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
import com.eltavine.duckdetector.capability.attestation.data.AttestedApplicationInfo
import com.eltavine.duckdetector.capability.attestation.data.AttestedAuthState
import com.eltavine.duckdetector.capability.attestation.data.AttestedDeviceInfo
import com.eltavine.duckdetector.capability.attestation.data.AttestedKeyProperties
import com.eltavine.duckdetector.capability.attestation.data.BootConsistencyResult
import com.eltavine.duckdetector.capability.attestation.data.CertificateTrustResult
import com.eltavine.duckdetector.capability.attestation.data.RootOfTrustSnapshot
import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import com.eltavine.duckdetector.capability.attestation.domain.TeeTrustRoot
import com.eltavine.duckdetector.features.tee.data.native.NativeTeeSnapshot
import com.eltavine.duckdetector.features.tee.data.verification.certificate.ChainStructureResult
import com.eltavine.duckdetector.features.tee.data.verification.certificate.DualAlgorithmChainResult
import com.eltavine.duckdetector.features.tee.data.verification.crl.CrlStatusResult
import com.eltavine.duckdetector.features.tee.data.verification.crl.RevokedCertificate
import com.eltavine.duckdetector.features.tee.data.verification.keystore.AesGcmRoundTripResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderChainConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderHookBootstrapResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BinderPatchModeResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.BiometricTeeIntegrationResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainFullChainSplitResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainFullChainSplitResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.IdAttestationResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ImportKeyRetainedAttestationNarrativeResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyLifecycleResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataSemanticsResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMetadataShapeResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyMintCapabilityResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyPairConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.KeyboxImportResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2GenerateModeParcelFingerprintResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2HookResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2PostProcessingResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.LegacyKeystorePathResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesBatchedResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ListEntriesConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationErrorPathResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OperationPruningResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.OversizedChallengeResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.PureCertificateSecurityLevelResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SupplementaryAttestationInfoAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SupplementaryAttestationInfoResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGetKeyEntryAccessVectorBlindnessResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingAnomalyResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingSideChannelResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentStaleResponsePersistenceResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.VintfKeyMintVersionAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.VintfKeyMintVersionResult
import com.eltavine.duckdetector.features.tee.data.verification.rkp.RkpProvisionedManufacturerResult
import com.eltavine.duckdetector.features.tee.data.verification.strongbox.StrongBoxBehaviorResult
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkMode
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkState
import com.eltavine.duckdetector.features.tee.domain.TeeRkpState
import com.eltavine.duckdetector.features.tee.domain.TeeSoterState

internal fun baseArtifacts(
    tier: TeeTier = TeeTier.TEE,
    chainStructure: ChainStructureResult = ChainStructureResult(
        chainLength = 3,
        attestationExtensionCount = 1,
        trustedAttestationIndex = 1,
        detail = "base",
    ),
    keystore2Hook: Keystore2HookResult = Keystore2HookResult(
        available = true,
        nativeStyleResponse = true,
        detail = "native",
    ),
    deviceInfo: AttestedDeviceInfo = AttestedDeviceInfo(brand = "duck", device = "duck"),
    idAttestation: IdAttestationResult = IdAttestationResult(
        mismatches = emptyList(),
        unavailableFields = emptyList(),
        detail = "ok",
    ),
    oversizedChallenge: OversizedChallengeResult = OversizedChallengeResult(
        acceptedOversizedChallenge = false,
        acceptedSizes = emptyList(),
        attemptedSizes = listOf(256, 512, 4096),
        detail = "ok",
    ),
    native: NativeTeeSnapshot = NativeTeeSnapshot(
        trickyStoreDetails = "clean",
    ),
    dualAlgorithm: DualAlgorithmChainResult = DualAlgorithmChainResult(
        mismatchDetected = false,
        detail = "ok",
    ),
    aesGcm: AesGcmRoundTripResult = AesGcmRoundTripResult(
        executed = true,
        roundTripSucceeded = true,
        keyInfoLevel = "TEE",
        insideSecureHardware = true,
        encryptMicros = 1600,
        decryptMicros = 1700,
        detail = "ok",
    ),
    timing: TimingAnomalyResult = TimingAnomalyResult(
        suspicious = false,
        medianMicros = 1800,
        detail = "ok",
    ),
    timingSideChannel: TimingSideChannelResult = TimingSideChannelResult(
        probeRan = false,
        measurementAvailable = false,
        timerSource = "unknown",
        affinity = "not_requested",
        failureReason = "skipped",
        detail = "skipped",
    ),
    strongBox: StrongBoxBehaviorResult = StrongBoxBehaviorResult(
        requested = false,
        advertised = false,
        available = false,
        detail = "skipped",
    ),
    bootConsistency: BootConsistencyResult = BootConsistencyResult(
        runtimePropsAvailable = true,
        runtimeVbmetaDigest = "12345678",
        detail = "Attested verifiedBootHash matched ro.boot.vbmeta.digest.",
    ),
    networkState: TeeNetworkState = TeeNetworkState(
        mode = TeeNetworkMode.INACTIVE,
        summary = "Offline-only verification",
    ),
    crlRevokedCertificates: List<RevokedCertificate> = emptyList(),
    trust: CertificateTrustResult = CertificateTrustResult(
        trustRoot = TeeTrustRoot.GOOGLE,
        chainLength = 3,
        chainSignatureValid = true,
        googleRootMatched = true,
    ),
    rkp: TeeRkpState = TeeRkpState(),
    soter: TeeSoterState = TeeSoterState(),
    keyMintCapability: KeyMintCapabilityResult = KeyMintCapabilityResult(
        executed = false,
    ),
    supplementaryAttestationInfo: SupplementaryAttestationInfoResult = SupplementaryAttestationInfoResult(
        available = false,
        anomalyKind = SupplementaryAttestationInfoAnomalyKind.UNSUPPORTED,
        detail = "skipped",
    ),
    vintfKeyMintVersion: VintfKeyMintVersionResult = VintfKeyMintVersionResult(
        readable = true,
        anomalyKind = VintfKeyMintVersionAnomalyKind.NO_DECLARATION,
        detail = "skipped",
    ),
    legacyKeystorePath: LegacyKeystorePathResult = LegacyKeystorePathResult(
        executed = false,
        detail = "skipped",
    ),
    listEntriesConsistency: ListEntriesConsistencyResult = ListEntriesConsistencyResult(
        executed = false,
        detail = "skipped",
    ),
    listEntriesBatched: ListEntriesBatchedResult = ListEntriesBatchedResult(
        executed = false,
        detail = "skipped",
    ),
    generateModeParcelFingerprint: Keystore2GenerateModeParcelFingerprintResult = Keystore2GenerateModeParcelFingerprintResult(
        executed = false,
        detail = "skipped",
    ),
    postProcessing: Keystore2PostProcessingResult = Keystore2PostProcessingResult(
        probeRan = false,
        detail = "skipped",
    ),
    rkpProvisionedManufacturer: RkpProvisionedManufacturerResult = RkpProvisionedManufacturerResult(
        probeRan = false,
        detail = "skipped",
    ),
    importKeyRetainedAttestationNarrative: ImportKeyRetainedAttestationNarrativeResult =
        ImportKeyRetainedAttestationNarrativeResult(
            executed = false,
            detail = "skipped",
        ),
    grantDomainFullChainSplit: GrantDomainFullChainSplitResult = GrantDomainFullChainSplitResult(
        detail = "skipped",
    ),
    syntheticGrantGranteeBlindReadback: SyntheticGrantGranteeBlindReadbackResult =
        SyntheticGrantGranteeBlindReadbackResult(
            detail = "skipped",
        ),
    syntheticGrantGetKeyEntryAccessVectorBlindness: SyntheticGrantGetKeyEntryAccessVectorBlindnessResult =
        SyntheticGrantGetKeyEntryAccessVectorBlindnessResult(
            detail = "skipped",
        ),
    grantSelfDomainFullChainSplit: GrantSelfDomainFullChainSplitResult = GrantSelfDomainFullChainSplitResult(
        detail = "skipped",
    ),
    keyMetadataSemantics: KeyMetadataSemanticsResult = KeyMetadataSemanticsResult(
        executed = false,
        detail = "skipped",
    ),
    keyMetadataShape: KeyMetadataShapeResult = KeyMetadataShapeResult(
        executed = false,
        detail = "skipped",
    ),
    pureCertificateSecurityLevel: PureCertificateSecurityLevelResult = PureCertificateSecurityLevelResult(
        executed = false,
        detail = "skipped",
    ),
    operationErrorPath: OperationErrorPathResult = OperationErrorPathResult(
        executed = false,
        detail = "skipped",
    ),
    biometricIntegration: BiometricTeeIntegrationResult = BiometricTeeIntegrationResult(
        executed = false,
        detail = "skipped",
    ),
    binderHookBootstrap: BinderHookBootstrapResult = BinderHookBootstrapResult(
        executed = false,
        detail = "skipped",
    ),
    binderPatchMode: BinderPatchModeResult = BinderPatchModeResult(
        executed = false,
        detail = "skipped",
    ),
    binderChainConsistency: BinderChainConsistencyResult = BinderChainConsistencyResult(
        executed = false,
        detail = "skipped",
    ),
    updateSubcomponentStaleResponsePersistence: UpdateSubcomponentStaleResponsePersistenceResult =
        UpdateSubcomponentStaleResponsePersistenceResult(
            detail = "skipped",
        ),
): TeeScanArtifacts {
    return TeeScanArtifacts(
        snapshot = AttestationSnapshot(
            tier = tier,
            attestationVersion = 4,
            keymasterVersion = 4,
            attestationTier = tier,
            keymasterTier = tier,
            challengeVerified = true,
            challengeSummary = "len=32",
            rootOfTrust = RootOfTrustSnapshot(
                verifiedBootKeyHex = "abcd",
                deviceLocked = true,
                verifiedBootState = "Verified",
                verifiedBootHashHex = "12345678",
            ),
            osVersion = "14.0.0",
            osPatchLevel = "2026-03",
            vendorPatchLevel = "2026-03-05",
            bootPatchLevel = "2026-03-05",
            keyProperties = AttestedKeyProperties(
                algorithm = "EC",
                keySize = 256,
                ecCurve = "P-256",
                origin = "Generated",
                rollbackResistant = true,
            ),
            authState = AttestedAuthState(noAuthRequired = true),
            applicationInfo = AttestedApplicationInfo(packageNames = listOf("com.eltavine.duckdetector")),
            deviceInfo = deviceInfo,
            deviceUniqueAttestation = false,
            trustedAttestationIndex = 1,
            rawCertificates = emptyList(),
            displayCertificates = emptyList(),
        ),
        trust = trust,
        chainStructure = chainStructure,
        rkp = rkp,
        crl = CrlStatusResult(
            networkState = networkState,
            revokedCertificates = crlRevokedCertificates,
        ),
        pairConsistency = KeyPairConsistencyResult(
            keyMatchesCertificate = true,
            medianSignMicros = 1800,
            detail = "ok",
        ),
        aesGcm = aesGcm,
        lifecycle = KeyLifecycleResult(
            created = true,
            deleteRemovedAlias = true,
            regeneratedFreshMaterial = true,
            detail = "ok",
        ),
        keyMintCapability = keyMintCapability,
        timing = timing,
        timingSideChannel = timingSideChannel,
        oversizedChallenge = oversizedChallenge,
        keyboxImport = KeyboxImportResult(
            executed = false,
            markerPreserved = true,
            marker = KeyboxImportProbe.FIXTURE_MARKER,
            detail = "skipped",
        ),
        importKeyRetainedAttestationNarrative = importKeyRetainedAttestationNarrative,
        supplementaryAttestationInfo = supplementaryAttestationInfo,
        vintfKeyMintVersion = vintfKeyMintVersion,
        keystore2Hook = keystore2Hook,
        generateModeParcelFingerprint = generateModeParcelFingerprint,
        postProcessing = postProcessing,
        rkpProvisionedManufacturer = rkpProvisionedManufacturer,
        grantDomainFullChainSplit = grantDomainFullChainSplit,
        syntheticGrantGranteeBlindReadback = syntheticGrantGranteeBlindReadback,
        syntheticGrantGetKeyEntryAccessVectorBlindness = syntheticGrantGetKeyEntryAccessVectorBlindness,
        grantSelfDomainFullChainSplit = grantSelfDomainFullChainSplit,
        legacyKeystorePath = legacyKeystorePath,
        listEntriesConsistency = listEntriesConsistency,
        listEntriesBatched = listEntriesBatched,
        keyMetadataSemantics = keyMetadataSemantics,
        keyMetadataShape = keyMetadataShape,
        pureCertificate = PureCertificateResult(
            pureCertificateReturnsNullKey = true,
            detail = "ok",
        ),
        pureCertificateSecurityLevel = pureCertificateSecurityLevel,
        operationErrorPath = operationErrorPath,
        biometricIntegration = biometricIntegration,
        binderHookBootstrap = binderHookBootstrap,
        binderPatchMode = binderPatchMode,
        binderChainConsistency = binderChainConsistency,
        updateSubcomponent = UpdateSubcomponentResult(
            updateSucceeded = true,
            keyNotFoundStyleFailure = false,
            detail = "ok",
        ),
        updateSubcomponentStaleResponsePersistence = updateSubcomponentStaleResponsePersistence,
        pruning = OperationPruningResult(
            suspicious = false,
            operationsCreated = 18,
            invalidatedOperations = 2,
            detail = "ok",
        ),
        dualAlgorithm = dualAlgorithm,
        idAttestation = idAttestation,
        strongBox = strongBox,
        native = native,
        soter = soter,
        bootConsistency = bootConsistency,
    )
}
