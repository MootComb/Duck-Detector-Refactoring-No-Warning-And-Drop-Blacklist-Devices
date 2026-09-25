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
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2PostProcessingAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SupplementaryAttestationInfoAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.VintfKeyMintVersionAnomalyKind
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkMode
import com.eltavine.duckdetector.features.tee.domain.TeePatchGrade
import com.eltavine.duckdetector.features.tee.domain.TeePatchState

internal fun tierValue(artifacts: TeeScanArtifacts): String {
    val effective = effectiveTier(artifacts)
    val snapshot = artifacts.snapshot
    val attest = snapshot.attestationTier?.displayName()
    val keymaster = snapshot.keymasterTier?.displayName()
    val strongBoxAttestation = artifacts.strongBox.attestationTier
        .takeIf { artifacts.strongBox.available || it == TeeTier.STRONGBOX }
        ?.displayName()
    return when {
        attest == null && keymaster == null && strongBoxAttestation == null -> effective.displayName()
        else -> buildString {
            append(effective.displayName())
            attest?.let {
                append(" • attest ")
                append(it)
            }
            keymaster?.let {
                append(" • keymaster ")
                append(it)
            }
            if (strongBoxAttestation != null && strongBoxAttestation != effective.displayName()) {
                append(" • sb attest ")
                append(strongBoxAttestation)
            }
        }
    }
}

internal fun effectiveTier(artifacts: TeeScanArtifacts): TeeTier {
    return when {
        artifacts.snapshot.tier == TeeTier.STRONGBOX -> TeeTier.STRONGBOX
        artifacts.snapshot.tier != TeeTier.TEE -> artifacts.snapshot.tier
        artifacts.strongBox.available && artifacts.strongBox.attestationTier == TeeTier.STRONGBOX ->
            TeeTier.STRONGBOX

        artifacts.strongBox.available && artifacts.strongBox.keyInfoLevel == "StrongBox" ->
            TeeTier.STRONGBOX

        else -> artifacts.snapshot.tier
    }
}

internal fun versionsValue(snapshot: AttestationSnapshot): String {
    val attestation = snapshot.attestationVersion?.toString() ?: "n/a"
    val keymaster = snapshot.keymasterVersion?.toString() ?: "n/a"
    val os = snapshot.osVersion ?: "n/a"
    return "attest $attestation • keymaster $keymaster • Android $os"
}

internal fun challengeValue(snapshot: AttestationSnapshot): String {
    return when {
        snapshot.trustedAttestationIndex == null -> "Unavailable"
        snapshot.challengeVerified -> snapshot.challengeSummary?.let { "Matched • $it" }
            ?: "Matched"

        else -> snapshot.challengeSummary?.let { "Mismatch • $it" } ?: "Mismatch"
    }
}

internal fun verifiedBootValue(snapshot: AttestationSnapshot): String {
    val root = snapshot.rootOfTrust ?: return "Unavailable"
    val state = root.verifiedBootState ?: "Unknown"
    val lock = when (root.deviceLocked) {
        true -> "locked"
        false -> "unlocked"
        null -> "lock unknown"
    }
    val hash = root.verifiedBootHashHex?.take(12)
    return buildString {
        append(state)
        append(" • ")
        append(lock)
        hash?.let {
            append(" • ")
            append(it)
        }
    }
}

private fun patchValue(patchState: TeePatchState): String {
    return buildString {
        append("runtime ")
        append(patchState.systemPatchLevel ?: "n/a")
        append(" • attest ")
        append(patchState.teePatchLevel ?: "n/a")
        if (patchState.vendorPatchLevel != null || patchState.bootPatchLevel != null) {
            append(" • vendor ")
            append(patchState.vendorPatchLevel ?: "n/a")
            append(" • boot ")
            append(patchState.bootPatchLevel ?: "n/a")
        }
    }
}

internal fun deviceInfoValue(snapshot: AttestationSnapshot): String {
    val labels = snapshot.deviceInfo.asDisplayMap().keys
    if (labels.isEmpty()) {
        return if (snapshot.deviceUniqueAttestation) {
            "No comparable IDs • unique attestation requested"
        } else {
            "Not included in attestation"
        }
    }
    return buildString {
        append(labels.joinToString(separator = ", "))
        if (snapshot.deviceUniqueAttestation) {
            append(" • unique")
        }
    }
}

internal fun keyPropertiesValue(snapshot: AttestationSnapshot): String {
    val props = snapshot.keyProperties
    return listOfNotNull(
        props.algorithm?.let { algorithm ->
            props.keySize?.let { "$algorithm $it" } ?: algorithm
        },
        props.ecCurve,
        props.origin,
        props.rollbackResistant.takeIf { it }?.let { "rollback resistant" },
    ).ifEmpty { listOf("Unavailable") }.joinToString(separator = " • ")
}

internal fun authStateValue(snapshot: AttestationSnapshot): String {
    val auth = snapshot.authState
    return when {
        auth.noAuthRequired == true -> "No user auth required"
        auth.userAuthTypes.isNotEmpty() -> buildString {
            append(auth.userAuthTypes.joinToString(separator = "/"))
            auth.authTimeoutSeconds?.let {
                append(" • ")
                append(it)
                append("s timeout")
            }
        }

        auth.trustedConfirmationRequired || auth.trustedPresenceRequired || auth.unlockedDeviceRequired -> {
            buildList {
                if (auth.trustedConfirmationRequired) add("confirmation")
                if (auth.trustedPresenceRequired) add("presence")
                if (auth.unlockedDeviceRequired) add("unlocked")
            }.joinToString(separator = " • ")
        }

        else -> "Unavailable"
    }
}

internal fun applicationInfoValue(snapshot: AttestationSnapshot): String {
    val packages = snapshot.applicationInfo.packageNames
    val digests = snapshot.applicationInfo.signatureDigestsSha256.size
    return when {
        packages.isNotEmpty() -> "${packages.size} package(s) • $digests signer digest(s)"
        snapshot.applicationInfo.rawBytesHex != null -> "Raw app attestation present"
        else -> "Unavailable"
    }
}

internal fun chainLayoutValue(artifacts: TeeScanArtifacts): String {
    val trustedIndex =
        artifacts.chainStructure.trustedAttestationIndex?.let { "#${it + 1}" } ?: "n/a"
    return "len ${artifacts.chainStructure.chainLength} • ext ${artifacts.chainStructure.attestationExtensionCount} • trusted $trustedIndex"
}

internal fun rkpValue(artifacts: TeeScanArtifacts): String {
    return when {
        artifacts.rkp.provisioned && !artifacts.trust.chainSignatureValid -> "Observed • local chain failed"
        artifacts.rkp.provisioned && hasLocalTrustReviewSignals(artifacts) -> "Observed • local trust needs review"
        artifacts.rkp.provisioned && artifacts.rkp.validityDays != null -> "Provisioned • ${artifacts.rkp.validityDays}d leaf"
        artifacts.rkp.provisioned -> "Provisioned"
        artifacts.rkp.consistencyIssue != null -> "Review provisioning"
        else -> "Not observed"
    }
}

internal fun crlValue(artifacts: TeeScanArtifacts): String {
    val network = artifacts.crl.networkState
    val sourceLabel = when {
        network.mode == TeeNetworkMode.ACTIVE -> "Online"
        network.mode == TeeNetworkMode.CONSENT_REQUIRED -> "Built-in snapshot"
        network.mode == TeeNetworkMode.SKIPPED -> "Built-in snapshot"
        network.mode == TeeNetworkMode.ERROR && network.usedCache -> "Built-in snapshot"
        network.mode == TeeNetworkMode.ERROR -> "Unavailable"
        network.mode == TeeNetworkMode.INACTIVE -> "Built-in snapshot"
        else -> "Built-in snapshot"
    }
    return buildString {
        append(sourceLabel)
        if (network.mode == TeeNetworkMode.ACTIVE || network.usedCache) {
            append(" • ")
            append(
                if (artifacts.crl.revokedCertificates.isEmpty()) {
                    "clean"
                } else if (hasLocalMassAbuseRevocation(artifacts) && !hasHardRevocation(artifacts)) {
                    "mass abuse"
                } else {
                    "${artifacts.crl.revokedCertificates.size} revoked"
                },
            )
        }
        network.detail?.takeIf { it.isNotBlank() }?.let { detail ->
            append(" • ")
            append(detail)
        }
    }
}

internal fun bootConsistencyValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.bootConsistency
    val root = artifacts.snapshot.rootOfTrust
    return when {
        result.hasHardAnomaly -> "Mismatch • ${result.detail}"
        root == null -> "Unavailable • ${result.detail}"
        !result.runtimePropsAvailable -> "Unavailable • ${result.detail}"
        result.runtimeComparisonPerformed ->
            "Matched • ${result.detail}"

        else -> "State only • ${result.detail}"
    }
}

private fun patchSignalValue(patchState: TeePatchState): String = when (patchState.grade) {
    TeePatchGrade.MATCHED -> "Aligned"
    TeePatchGrade.WARNING -> "Short drift"
    TeePatchGrade.SUSPICIOUS -> "Wide drift"
    TeePatchGrade.UNKNOWN -> "Unavailable"
}

internal fun crlSignalValue(artifacts: TeeScanArtifacts): String = when {
    hasHardRevocation(artifacts) -> "Revoked"
    hasLocalMassAbuseRevocation(artifacts) -> "Mass abuse"
    artifacts.crl.networkState.mode == TeeNetworkMode.ACTIVE -> "Online"
    artifacts.crl.networkState.mode == TeeNetworkMode.CONSENT_REQUIRED -> "Built-in"
    artifacts.crl.networkState.mode == TeeNetworkMode.SKIPPED -> "Built-in"
    artifacts.crl.networkState.mode == TeeNetworkMode.ERROR && artifacts.crl.networkState.usedCache -> "Built-in"
    artifacts.crl.networkState.mode == TeeNetworkMode.ERROR -> "Error"
    else -> "Offline"
}

internal fun bootSignalValue(artifacts: TeeScanArtifacts): String {
    val root = artifacts.snapshot.rootOfTrust
    return when {
        artifacts.bootConsistency.hasHardAnomaly -> "Mismatch"
        root == null -> "Unavailable"
        !artifacts.bootConsistency.runtimePropsAvailable -> "Unavailable"
        artifacts.bootConsistency.runtimeComparisonPerformed -> "Matched"
        else -> "State only"
    }
}

internal fun vintfKeyMintVersionValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.vintfKeyMintVersion
    return when (result.anomalyKind) {
        VintfKeyMintVersionAnomalyKind.MISMATCH -> if (keyMintRuntimeIdentityMismatch(artifacts)) {
            "Attestation and keymaster versions violate the AOSP single-runtime mapping. ${result.detail}"
        } else {
            "VINTF declaration did not match attested version. ${result.detail}"
        }
        VintfKeyMintVersionAnomalyKind.NONE ->
            "VINTF declaration matched attested KeyMint version. ${result.detail}"
        VintfKeyMintVersionAnomalyKind.UNREADABLE ->
            "VINTF manifest was not fully readable. ${result.detail}"
        VintfKeyMintVersionAnomalyKind.NO_DECLARATION ->
            "No comparable KeyMint VINTF declaration was found. ${result.detail}"
        VintfKeyMintVersionAnomalyKind.NO_ATTESTED_VERSION ->
            "Attested KeyMint version was unavailable. ${result.detail}"
    }
}

internal fun postProcessingValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.postProcessing
    return when (result.anomalyKind) {
        Keystore2PostProcessingAnomalyKind.ROOT_OF_TRUST_DIVERGENCE ->
            "RootOfTrust differed between the RKP and ATTEST_KEY paths, which only certificate post-processing explains. ${result.detail}"
        Keystore2PostProcessingAnomalyKind.TIMING_DETECTED ->
            "The RKP path cost significantly more than the ATTEST_KEY path, matching certificate post-processing. ${result.detail}"
        Keystore2PostProcessingAnomalyKind.TIMING_SUSPECT ->
            "The RKP path was slower than the ATTEST_KEY path, but not far enough above this device's own noise to call. ${result.detail}"
        Keystore2PostProcessingAnomalyKind.NONE ->
            "The RKP and ATTEST_KEY paths agreed, showing no sign of certificate post-processing. ${result.detail}"
        Keystore2PostProcessingAnomalyKind.RKP_UNAVAILABLE ->
            "RKP key acquisition hard-failed, so the post-processing path could not be reached or tested. ${result.detail}"
        Keystore2PostProcessingAnomalyKind.RKP_FALLBACK_INCONCLUSIVE ->
            "The factory key was used instead of an RKP key, so the post-processing path was never traversed and this is untested rather than clean. ${result.detail}"
        Keystore2PostProcessingAnomalyKind.UNMEASURABLE ->
            "Not enough paired samples were collected to judge certificate post-processing. ${result.detail}"
    }
}

internal fun rkpProvisionedManufacturerValue(artifacts: TeeScanArtifacts): String =
    artifacts.rkpProvisionedManufacturer.detail

internal fun supplementaryAttestationInfoValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.supplementaryAttestationInfo
    return when (result.anomalyKind) {
        SupplementaryAttestationInfoAnomalyKind.MISSING_ATTESTATION_MODULE_HASH ->
            "MODULE_HASH omitted from attestation. ${result.detail}"
        SupplementaryAttestationInfoAnomalyKind.MISMATCH ->
            "MODULE_HASH did not match supplementary attestation info. ${result.detail}"
        SupplementaryAttestationInfoAnomalyKind.UNEXPECTED_ATTESTATION_MODULE_HASH ->
            "MODULE_HASH present while supplementary attestation info was unavailable. ${result.detail}"
        SupplementaryAttestationInfoAnomalyKind.NONE ->
            if (result.attestedModuleHashHex == null) {
                "MODULE_HASH not required by attestation version. ${result.detail}"
            } else {
                "MODULE_HASH matched supplementary attestation info. ${result.detail}"
            }
        SupplementaryAttestationInfoAnomalyKind.UNSUPPORTED ->
            "Unavailable. ${result.detail}"
    }
}
