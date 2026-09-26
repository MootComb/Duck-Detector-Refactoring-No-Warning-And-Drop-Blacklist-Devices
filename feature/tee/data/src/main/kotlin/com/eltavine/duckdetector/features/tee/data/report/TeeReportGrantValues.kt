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
