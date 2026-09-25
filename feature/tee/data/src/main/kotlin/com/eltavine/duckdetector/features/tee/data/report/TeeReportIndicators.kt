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

import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceItem
import com.eltavine.duckdetector.features.tee.domain.TeePatchState
import com.eltavine.duckdetector.features.tee.domain.TeeSignal
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict

internal fun determineVerdict(
    artifacts: TeeScanArtifacts,
    policyHardIndicators: List<TeeEvidenceItem>,
    policySoftIndicators: List<TeeEvidenceItem>,
): TeeVerdict {
    val tier = effectiveTier(artifacts)
    return when {
        policyHardIndicators.isNotEmpty() -> TeeVerdict.TAMPERED
        tier == TeeTier.NONE -> TeeVerdict.BROKEN
        tier == TeeTier.SOFTWARE -> TeeVerdict.BROKEN
        tier == TeeTier.UNKNOWN && artifacts.snapshot.rawCertificates.isEmpty() -> TeeVerdict.BROKEN
        policySoftIndicators.isNotEmpty() -> TeeVerdict.SUSPICIOUS
        tier == TeeTier.TEE || tier == TeeTier.STRONGBOX -> TeeVerdict.CONSISTENT
        else -> TeeVerdict.INCONCLUSIVE
    }
}

internal fun collectPolicyHardIndicators(artifacts: TeeScanArtifacts): List<TeeEvidenceItem> {
    return buildList {
        if (!artifacts.trust.chainSignatureValid) {
            add(
                fact(
                    "Chain signature",
                    "Certificate signatures did not verify locally.",
                    TeeSignalLevel.FAIL
                )
            )
        }
        if (artifacts.snapshot.trustedAttestationIndex != null && !artifacts.snapshot.challengeVerified) {
            add(
                fact(
                    "Challenge",
                    "Attestation challenge did not match the local request.",
                    TeeSignalLevel.FAIL
                )
            )
        }
        if (artifacts.bootConsistency.vbmetaDigestMismatch) {
            add(
                fact(
                    "Boot consistency",
                    "Attested verifiedBootHash did not match ro.boot.vbmeta.digest.",
                    TeeSignalLevel.FAIL
                )
            )
        }
        if (artifacts.bootConsistency.vbmetaDigestMissingWhileAttestedHashPresent) {
            add(
                fact(
                    "Boot consistency",
                    "Attested verifiedBootHash was present, but ro.boot.vbmeta.digest was empty.",
                    TeeSignalLevel.FAIL
                )
            )
        }
        if (artifacts.bootConsistency.verifiedBootHashAllZeros) {
            add(
                fact(
                    "Verified boot hash",
                    "Attested verifiedBootHash was all zeros.",
                    TeeSignalLevel.FAIL
                )
            )
        }
        if (artifacts.bootConsistency.verifiedBootKeyAllZeros) {
            add(
                fact(
                    "Verified boot key",
                    "Attested verifiedBootKey was all zeros.",
                    TeeSignalLevel.FAIL
                )
            )
        }
        if (hasHardRevocation(artifacts)) {
            add(
                fact(
                    "Revocation",
                    "Revocation data matched certificate serials from the chain.",
                    TeeSignalLevel.FAIL
                )
            )
        }
        if (artifacts.soter.damaged) {
            add(fact("Soter", artifacts.soter.summary, TeeSignalLevel.FAIL))
        }
    }
}

internal fun collectPolicySoftIndicators(
    artifacts: TeeScanArtifacts,
    patchState: TeePatchState,
): List<TeeEvidenceItem> {
    return buildList {
        artifacts.snapshot.errorMessage?.takeIf { it.isNotBlank() }?.let { message ->
            add(fact("Collector", message, TeeSignalLevel.WARN))
        }
        artifacts.chainStructure.issuerMismatches.forEach { mismatch ->
            add(fact("Issuer path", mismatch, TeeSignalLevel.WARN))
        }
        artifacts.chainStructure.expiredCertificates.forEach { expired ->
            add(fact("Certificate validity", expired, TeeSignalLevel.WARN))
        }
        if (artifacts.chainStructure.provisioningConsistencyIssue) {
            add(
                fact(
                    "Provisioning layout",
                    "Provisioning info was not adjacent to the trusted attestation certificate.",
                    TeeSignalLevel.WARN
                )
            )
        }
        if (artifacts.oversizedChallenge.acceptedOversizedChallenge) {
            add(
                fact(
                    "Oversized challenge",
                    "Attestation accepted oversized challenge sizes: ${artifacts.oversizedChallenge.acceptedSizesLabel()}.",
                    TeeSignalLevel.WARN
                )
            )
        }
        artifacts.rkp.consistencyIssue?.let { issue ->
            add(fact("RKP consistency", issue, TeeSignalLevel.WARN))
        }
        if (hasLocalMassAbuseRevocation(artifacts)) {
            add(
                fact(
                    "Revocation",
                    "Built-in local revocation floor matched a certificate serial associated with mass abuse.",
                    TeeSignalLevel.WARN,
                )
            )
        }
    }
}

internal fun buildSignals(
    artifacts: TeeScanArtifacts,
    patchState: TeePatchState,
    policyHardIndicators: List<TeeEvidenceItem>,
    policySoftIndicators: List<TeeEvidenceItem>,
    supplementaryIndicators: List<TeeEvidenceItem>,
): List<TeeSignal> {
    return buildList {
        add(
            TeeSignal(
                "Local chain",
                if (artifacts.trust.chainSignatureValid) "Verified" else "Failed",
                if (artifacts.trust.chainSignatureValid) TeeSignalLevel.PASS else TeeSignalLevel.FAIL
            )
        )
        add(TeeSignal("Boot", bootSignalValue(artifacts), bootSignalLevel(artifacts)))
        add(
            TeeSignal(
                "Signals",
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
            ),
        )
        if (generateModeAnomalyState(artifacts) == GenerateModeAnomalyState.MATCHED) {
            add(TeeSignal("TEE Simulator generate-mode fingerprint", "Matched", TeeSignalLevel.FAIL))
        }
        add(TeeSignal("CRL", crlSignalValue(artifacts), crlSignalLevel(artifacts)))
        if (artifacts.native.trickyStoreDetected || artifacts.native.leafDerPrimaryDetected || artifacts.native.leafDerSecondaryDetected) {
            add(TeeSignal("Native", nativeSignalValue(artifacts), nativeSignalLevel(artifacts)))
        }
        if (artifacts.keystore2Hook.available || artifacts.keystore2Hook.javaHookDetected) {
            add(
                TeeSignal(
                    "Keystore2",
                    keystore2Value(artifacts),
                    if (artifacts.keystore2Hook.javaHookDetected) TeeSignalLevel.FAIL else TeeSignalLevel.INFO,
                ),
            )
        }
    }
}
