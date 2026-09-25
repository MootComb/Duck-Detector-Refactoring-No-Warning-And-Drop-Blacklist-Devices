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

import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackAnomalyKind
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel

internal fun grantDomainFullChainSplitValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.grantDomainFullChainSplit
    return when {
        result.executed && result.splitDetected -> buildString {
            append("Matched")
            append(" kind=")
            append(result.anomalyKind.name)
            append(" owner=")
            append(result.ownerChainLength)
            append(" grantee=")
            append(result.granteeChainLength)
            result.mismatchIndex?.let { append(" mismatchIndex=$it") }
            result.granteeUid?.let { append(" uid=$it") }
            result.detail.takeIf { it.isNotBlank() }?.let { append(" • $it") }
        }
        result.executed && result.available -> buildString {
            append("Clean")
            append(" kind=")
            append(result.anomalyKind.name)
            append(" length=")
            append(result.ownerChainLength)
            result.granteeUid?.let { append(" uid=$it") }
            result.detail.takeIf { it.isNotBlank() }?.let { append(" • $it") }
        }
        else -> buildString {
            append("Unavailable")
            append(" kind=")
            append(result.anomalyKind.name)
            result.ownerChainLength.takeIf { it > 0 }?.let { append(" owner=$it") }
            result.granteeUid?.let { append(" uid=$it") }
            result.detail.takeIf { it.isNotBlank() }?.let { append(" • $it") }
        }
    }
}

internal fun syntheticGrantGranteeBlindReadbackValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.syntheticGrantGranteeBlindReadback
    return when {
        result.anomalyKind == SyntheticGrantGranteeBlindReadbackAnomalyKind.NON_GRANTEE_READBACK_ALLOWED ->
            buildString {
                append("Matched kind=NON_GRANTEE_READBACK_ALLOWED")
                result.granteeUid?.let { append(" uid=$it") }
                append(" ownerReplay=true")
                result.detail.takeIf { it.isNotBlank() }?.let { append(" • $it") }
            }
        result.executed && result.available &&
            result.anomalyKind == SyntheticGrantGranteeBlindReadbackAnomalyKind.NONE ->
            buildString {
                append("Clean kind=NONE")
                result.granteeUid?.let { append(" uid=$it") }
                append(" ownerReplay=KEY_NOT_FOUND")
                result.detail.takeIf { it.isNotBlank() }?.let { append(" • $it") }
            }
        result.anomalyKind == SyntheticGrantGranteeBlindReadbackAnomalyKind.SKIPPED_AFTER_EXISTING_GRANT_DANGER ->
            "Skipped • ${result.detail}"
        else -> buildString {
            append("Unavailable kind=")
            append(result.anomalyKind.name)
            result.ownerReplayErrorKind?.let { append(" ownerReplay=$it") }
            result.detail.takeIf { it.isNotBlank() }?.let { append(" • $it") }
        }
    }
}

internal fun syntheticGrantGetKeyEntryAccessVectorBlindnessValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.syntheticGrantGetKeyEntryAccessVectorBlindness
    return when {
        result.anomalyKind ==
            SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.GET_KEY_ENTRY_WITHOUT_GET_INFO_ALLOWED ->
            buildString {
                append("Matched kind=GET_KEY_ENTRY_WITHOUT_GET_INFO_ALLOWED")
                result.granteeUid?.let { append(" uid=$it") }
                result.accessVector?.let { append(" accessVector=$it") }
                append(" granteeRead=true")
                result.detail.takeIf { it.isNotBlank() }?.let { append(" • $it") }
            }
        result.executed && result.available &&
            result.anomalyKind == SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.NONE ->
            buildString {
                append("Clean kind=NONE")
                result.granteeUid?.let { append(" uid=$it") }
                result.accessVector?.let { append(" accessVector=$it") }
                append(" granteeRead=PERMISSION_DENIED")
                result.detail.takeIf { it.isNotBlank() }?.let { append(" • $it") }
            }
        result.anomalyKind ==
            SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.SKIPPED_AFTER_EXISTING_GRANT_DANGER ->
            "Skipped • ${result.detail}"
        else -> buildString {
            append("Unavailable kind=")
            append(result.anomalyKind.name)
            result.granteeReadErrorKind?.let { append(" granteeRead=$it") }
            result.accessVector?.let { append(" accessVector=$it") }
            result.detail.takeIf { it.isNotBlank() }?.let { append(" • $it") }
        }
    }
}

internal fun grantSelfDomainFullChainSplitValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.grantSelfDomainFullChainSplit
    return when {
        result.anomalyKind == GrantSelfDomainAnomalyKind.SELF_GRANT_ATTESTATION_APP_KEY_NOT_FOUND ->
            buildString {
                append("Matched")
                append(" kind=")
                append(result.anomalyKind.name)
                if (result.grantIdPresent) append(" grantId=true")
                result.detail.takeIf { it.isNotBlank() }?.let { append(" • $it") }
            }

        result.executed && result.splitDetected -> buildString {
            append("Matched")
            append(" kind=")
            append(result.anomalyKind.name)
            append(" owner=")
            append(result.ownerChainLength)
            append(" grant=")
            append(result.grantChainLength)
            result.mismatchIndex?.let { append(" mismatchIndex=$it") }
            if (result.grantIdPresent) append(" grantId=true")
            result.detail.takeIf { it.isNotBlank() }?.let { append(" • $it") }
        }

        result.executed && result.available -> buildString {
            append("Clean")
            append(" kind=")
            append(result.anomalyKind.name)
            append(" length=")
            append(result.ownerChainLength)
            if (result.grantIdPresent) append(" grantId=true")
            result.detail.takeIf { it.isNotBlank() }?.let { append(" • $it") }
        }

        else -> buildString {
            append("Unavailable")
            append(" kind=")
            append(result.anomalyKind.name)
            result.ownerChainLength.takeIf { it > 0 }?.let { append(" owner=$it") }
            if (result.grantIdPresent) append(" grantId=true")
            result.detail.takeIf { it.isNotBlank() }?.let { append(" • $it") }
        }
    }
}

internal fun pureCertificateValue(artifacts: TeeScanArtifacts): String {
    return if (!artifacts.pureCertificate.executed) {
        notRunValue(artifacts.pureCertificate.probeError)
    } else if (artifacts.pureCertificate.pureCertificateReturnsNullKey) {
        "Null key as expected"
    } else {
        "Returned a key object"
    }
}

internal fun pureCertificateTopLevelSecurityValue(artifacts: TeeScanArtifacts): String {
    return when {
        !artifacts.pureCertificateSecurityLevel.executed -> "Skipped"
        artifacts.pureCertificateSecurityLevel.securityLevelPresent -> "Security level exposed"
        else -> "No security level exposed"
    }
}

internal fun pureCertificateMetadataSecurityValue(artifacts: TeeScanArtifacts): String {
    return when {
        !artifacts.pureCertificateSecurityLevel.executed -> "Skipped"
        artifacts.pureCertificateSecurityLevel.metadataSecurityLevelPresent -> "Metadata security level exposed"
        else -> "No metadata security level exposed"
    }
}

internal fun keyMetadataSemanticsValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.keyMetadataSemantics
    return when {
        !result.executed -> "Skipped"
        result.usesKeyIdDomain && result.aliasCleared -> "KEY_ID normalized"
        else -> "Descriptor mismatch"
    }
}

internal fun keyMetadataShapeValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.keyMetadataShape
    return when {
        !result.executed -> "Skipped"
        result.modificationTimeValid && result.hasOriginTag -> "System fields present"
        else -> "System fields missing"
    }
}

internal fun operationErrorPathValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.operationErrorPath
    val status = when {
        !result.executed -> "Skipped"
        !result.createOperationSucceeded -> "createOperation failed"
        !result.updateAadServiceSpecific -> "updateAad mismatch"
        !result.oversizedUpdateRejected -> "Oversized update accepted"
        !result.abortInvalidatedHandle -> "Abort left operation alive"
        result.fallbackCompatParamsUsed -> "Compatibility params required"
        else -> "Native-style errors"
    }
    val detail = result.detail.takeIf { it.isNotBlank() } ?: return status
    return "$status • $detail"
}

internal fun updateSubcomponentValue(artifacts: TeeScanArtifacts): String {
    val base = when {
        !artifacts.updateSubcomponent.executed -> notRunValue(artifacts.updateSubcomponent.probeError)
        artifacts.updateSubcomponent.keyNotFoundStyleFailure -> "Key-not-found style failure"
        artifacts.updateSubcomponent.updateSucceeded -> "No anomaly"
        else -> "Unexpected failure"
    }
    val grant = grantUpdateSubcomponentValue(artifacts)
    return if (grant == "Skipped") base else "$base • Grant $grant"
}

private fun grantUpdateSubcomponentValue(artifacts: TeeScanArtifacts): String {
    val crypto = artifacts.keyMintCapability.crypto
    return when {
        !artifacts.keyMintCapability.executed || !crypto.grantUpdateSubcomponentExecuted -> "Skipped"
        crypto.grantUpdateSubcomponentOk -> "ok"
        else -> "failed: ${crypto.grantUpdateSubcomponentDetail}"
    }
}

internal fun updateSubcomponentFailureSummary(artifacts: TeeScanArtifacts): String {
    val failures = buildList {
        if (artifacts.updateSubcomponent.keyNotFoundStyleFailure) {
            add("setKeyEntry() failed with a key-not-found style response")
        }
        if (grantUpdateSubcomponentFailed(artifacts)) {
            add("Domain.GRANT updateSubcomponent did not round-trip cert/chain metadata")
        }
    }
    return failures.joinToString("; ") + "."
}

internal fun grantUpdateSubcomponentFailed(artifacts: TeeScanArtifacts): Boolean {
    val crypto = artifacts.keyMintCapability.crypto
    return artifacts.keyMintCapability.executed &&
        crypto.grantUpdateSubcomponentExecuted &&
        !crypto.grantUpdateSubcomponentOk
}

internal fun updateSubcomponentLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    artifacts.updateSubcomponent.keyNotFoundStyleFailure || grantUpdateSubcomponentFailed(artifacts) ->
        TeeSignalLevel.FAIL
    !artifacts.updateSubcomponent.executed || !artifacts.updateSubcomponent.updateSucceeded -> TeeSignalLevel.INFO
    else -> TeeSignalLevel.PASS
}

internal fun updateSubcomponentStaleResponsePersistenceValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.updateSubcomponentStaleResponsePersistence
    return when {
        result.staleNarrativeDetected -> buildString {
            append("Matched kind=")
            append(result.anomalyKind.name)
            append(" retained=")
            append(result.retainedCertificateCount)
            append(" prior=")
            append(result.priorChainLength)
            append(" post=")
            append(result.postChainLength)
            append(" leafMatchesMarker=")
            append(result.postLeafMatchesMarker)
            result.retainedFingerprint?.let { append(" retainedSha=$it") }
            result.detail.takeIf { it.isNotBlank() }?.let { append(" • $it") }
        }

        result.executed && result.available -> buildString {
            append("Clean kind=")
            append(result.anomalyKind.name)
            append(" prior=")
            append(result.priorChainLength)
            append(" post=")
            append(result.postChainLength)
            append(" leafMatchesMarker=")
            append(result.postLeafMatchesMarker)
            result.detail.takeIf { it.isNotBlank() }?.let { append(" • $it") }
        }

        else -> buildString {
            append("Unavailable kind=")
            append(result.anomalyKind.name)
            result.priorChainLength.takeIf { it > 0 }?.let { append(" prior=$it") }
            result.postChainLength.takeIf { it > 0 }?.let { append(" post=$it") }
            append(" supportGate=")
            append(result.supportGateClean)
            append(" updateSucceeded=")
            append(result.updateSucceeded)
            result.detail.takeIf { it.isNotBlank() }?.let { append(" • $it") }
        }
    }
}

internal fun pruningValue(artifacts: TeeScanArtifacts): String {
    return if (artifacts.pruning.operationsCreated == 0) {
        "Skipped"
    } else {
        "${artifacts.pruning.invalidatedOperations}/${artifacts.pruning.operationsCreated} invalidated"
    }
}

internal fun dualAlgorithmValue(artifacts: TeeScanArtifacts): String {
    return if (!artifacts.dualAlgorithm.executed) {
        notRunValue(artifacts.dualAlgorithm.probeError)
    } else if (artifacts.dualAlgorithm.mismatchDetected) {
        "RSA/EC chain difference observed"
    } else {
        "RSA/EC chains aligned"
    }
}

internal fun idAttestationValue(artifacts: TeeScanArtifacts): String {
    return when {
        !artifacts.idAttestation.probeRan -> "Skipped"
        artifacts.idAttestation.mismatches.isNotEmpty() -> "${artifacts.idAttestation.mismatches.size} mismatch(es)"
        artifacts.idAttestation.unavailableFields.size >= 5 -> "No comparable IDs exposed"
        artifacts.idAttestation.unavailableFields.isNotEmpty() -> "${artifacts.idAttestation.unavailableFields.size} comparable field(s) not exposed"
        else -> "Available fields aligned"
    }
}

internal fun biometricIntegrationValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.biometricIntegration
    return when {
        !result.executed -> "Skipped"
        !result.strongBiometricAvailable -> "Strong biometric unavailable"
        result.keyCreated && result.keyRetrieved -> "User-auth key path available"
        result.keyCreated -> "Created but getKey() returned null"
        else -> "User-auth key path failed"
    }
}

internal fun binderChainConsistencyValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.binderChainConsistency
    val status = when {
        !result.executed -> "Skipped"
        !result.hookInstalled -> "Hook bootstrap failed"
        result.suspiciousLeafIssuerSpki -> "Leaf SPKI matched issuer SPKI"
        !result.activeProbeSecondCycleSucceeded -> "Repeated active probe failed"
        !result.deleteEntryRemovedAlias -> "deleteEntry left alias present"
        !result.keystoreChainAvailable -> "Java chain unavailable"
        !result.binderMaterialAvailable -> "Binder chain unavailable"
        !result.generateVsGetKeyEntryLeafMatches -> "generateKey leaf differed from getKeyEntry"
        !result.generateVsGetKeyEntryChainMatches -> "generateKey chain differed from getKeyEntry"
        result.chainMatches -> "Java and binder chains aligned"
        result.leafMatches -> "Leaf matched but chain diverged"
        else -> "Leaf and chain diverged"
    }
    val detail = result.detail.takeIf { it.isNotBlank() } ?: return status
    return "$status • $detail"
}

internal fun binderHookBootstrapValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.binderHookBootstrap
    return when {
        !result.executed -> "Skipped"
        result.hookInstalled -> "Hook installed"
        else -> "Hook bootstrap failed"
    }
}

internal fun legacyKeystorePathValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.legacyKeystorePath
    return when {
        !result.executed -> "Skipped"
        !result.hookInstalled -> "Hook unavailable"
        !result.legacyMaterialAvailable -> "Legacy path not observed"
        result.chainMatches -> "Legacy path aligned"
        result.userCertCaptured || result.caCertCaptured -> "Legacy path captured but diverged"
        else -> "Legacy path unavailable"
    }
}

internal fun binderPatchModeValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.binderPatchMode
    return when {
        !result.executed -> "Skipped"
        !result.hookInstalled -> "Hook unavailable"
        result.leafDiffers -> "Leaf differed between generateKey and getKeyEntry"
        result.chainDiffers -> "Chain differed between generateKey and getKeyEntry"
        result.generateMaterialAvailable && result.keyEntryMaterialAvailable -> "generateKey/getKeyEntry aligned"
        else -> "Capture unavailable"
    }
}

internal fun strongBoxValue(artifacts: TeeScanArtifacts): String {
    val strongBox = artifacts.strongBox
    if (strongBox.hardFailures.isNotEmpty()) {
        return strongBox.hardFailures.first()
    }
    val state = when {
        !strongBox.requested && !strongBox.advertised -> "Not advertised"
        strongBox.available -> buildString {
            append("Available")
            strongBox.keyInfoLevel?.let {
                append(" • ")
                append(it)
            }
        }

        // "Not confirmed" covers both a key that came back without StrongBox backing and a probe
        // that never got an answer. Only the first is evidence about the device, so name the
        // reason whenever the probe recorded one.
        strongBox.requested -> buildString {
            append("Not confirmed")
            strongBox.keyInfoUnavailableDetail.takeIf(String::isNotBlank)?.let {
                append(" • ")
                append(it)
            }
        }

        else -> "Skipped"
    }
    // Warnings follow the state instead of replacing it. They are INFO-level notes here, and a
    // working StrongBox that signed quickly is still a working StrongBox, so leading with the
    // note used to hide both availability and the reported key level. All of them are kept
    // because showing only the first dropped the rest.
    return if (strongBox.warnings.isEmpty()) {
        state
    } else {
        (listOf(state) + strongBox.warnings).joinToString(" • ")
    }
}

internal fun listEntriesConsistencyValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.listEntriesConsistency
    return when {
        !result.executed -> "Skipped"
        result.badParcelableLikeCrash -> "BadParcelable-style crash"
        result.inconsistent -> "containsAlias/listEntries mismatch"
        else -> "containsAlias and aliases aligned"
    }
}

internal fun listEntriesBatchedValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.listEntriesBatched
    return when {
        !result.executed -> "Skipped"
        result.cursorEchoed -> "Cursor echoed in page"
        result.expectedNextMissing -> "Expected next alias missing"
        else -> "Cursor semantics aligned"
    }
}
