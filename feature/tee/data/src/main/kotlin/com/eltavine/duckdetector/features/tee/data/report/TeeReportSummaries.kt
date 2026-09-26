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

import android.os.Build
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceItem
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceTopic
import com.eltavine.duckdetector.features.tee.domain.TeeGrantEvidence
import com.eltavine.duckdetector.features.tee.domain.TeePatchGrade
import com.eltavine.duckdetector.features.tee.domain.TeePatchState
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict

internal fun buildPatchState(artifacts: TeeScanArtifacts): TeePatchState {
    val runtimePatch = Build.VERSION.SECURITY_PATCH?.takeIf { it.isNotBlank() }
    val attestedPatch = artifacts.snapshot.osPatchLevel
    val grade = when {
        runtimePatch == null || attestedPatch == null -> TeePatchGrade.UNKNOWN
        runtimePatch == attestedPatch -> TeePatchGrade.MATCHED
        monthDistance(
            runtimePatch,
            attestedPatch
        )?.let { it <= 3 } == true -> TeePatchGrade.WARNING

        else -> TeePatchGrade.SUSPICIOUS
    }
    return TeePatchState(
        systemPatchLevel = runtimePatch,
        teePatchLevel = attestedPatch,
        vendorPatchLevel = artifacts.snapshot.vendorPatchLevel,
        bootPatchLevel = artifacts.snapshot.bootPatchLevel,
        grade = grade,
        summary = when (grade) {
            TeePatchGrade.MATCHED -> "Runtime and attested patch levels line up locally."
            TeePatchGrade.WARNING -> "Patch levels drift slightly but stay within a short window."
            TeePatchGrade.SUSPICIOUS -> "Runtime and attested patch levels drift by more than three months."
            TeePatchGrade.UNKNOWN -> "Patch comparison was unavailable."
        },
    )
}

internal fun headlineFor(
    verdict: TeeVerdict,
    supplementaryIndicators: List<TeeEvidenceItem>,
    nativeProbesAvailable: Boolean,
): String = when (verdict) {
    TeeVerdict.CONSISTENT -> when {
        supplementaryIndicators.isNotEmpty() -> "Attestation aligned; local probes need review"
        !nativeProbesAvailable -> "Attestation aligned; native probes did not run"
        else -> "Local TEE attestation checks aligned"
    }

    TeeVerdict.TAMPERED -> "Policy-backed attestation anomalies were detected"
    TeeVerdict.SUSPICIOUS -> "Policy-backed attestation evidence needs review"
    TeeVerdict.BROKEN -> "Hardware-backed local verification was not established"
    TeeVerdict.INCONCLUSIVE -> "Local verification stayed inconclusive"
    TeeVerdict.LOADING -> "TEE"
}

/** The indicator whose body [summaryFor] quotes for [verdict], if it quotes one. */
internal fun summarySourceFor(
    verdict: TeeVerdict,
    policyHardIndicators: List<TeeEvidenceItem>,
    policySoftIndicators: List<TeeEvidenceItem>,
    supplementaryIndicators: List<TeeEvidenceItem>,
): TeeEvidenceItem? = when (verdict) {
    TeeVerdict.CONSISTENT -> supplementaryIndicators.highestPriority()
    TeeVerdict.TAMPERED -> policyHardIndicators.firstOrNull()
    TeeVerdict.SUSPICIOUS -> policySoftIndicators.firstOrNull()
    TeeVerdict.BROKEN,
    TeeVerdict.INCONCLUSIVE,
    TeeVerdict.LOADING -> null
}

internal fun summaryFor(
    verdict: TeeVerdict,
    artifacts: TeeScanArtifacts,
    policyHardIndicators: List<TeeEvidenceItem>,
    policySoftIndicators: List<TeeEvidenceItem>,
    supplementaryIndicators: List<TeeEvidenceItem>,
    nativeProbesAvailable: Boolean,
): String = when (verdict) {
    TeeVerdict.CONSISTENT -> supplementaryIndicators.highestPriority()?.let { item ->
        "${item.body} Attestation and trust-path checks still aligned."
    } ?: if (nativeProbesAvailable) {
        "Attestation, trust path, and revocation checks line up."
    } else {
        "Attestation, trust path, and revocation checks line up, but the native process-side probes did not run."
    }

    TeeVerdict.TAMPERED -> policyHardIndicators.firstOrNull()?.body
        ?: "Multiple hard anomaly indicators were raised."

    TeeVerdict.SUSPICIOUS -> policySoftIndicators.firstOrNull()?.body
        ?: "Policy-backed review signals suggest further review."

    TeeVerdict.BROKEN -> artifacts.snapshot.errorMessage
        ?: "Local verification could not establish hardware-backed trust."

    TeeVerdict.INCONCLUSIVE -> "Signals were mixed and did not converge on a stable local result."
    TeeVerdict.LOADING -> "Collecting local attestation and keystore evidence."
}

internal fun collapsedSummaryFor(
    verdict: TeeVerdict,
    policyHardIndicators: List<TeeEvidenceItem>,
    policySoftIndicators: List<TeeEvidenceItem>,
    supplementaryIndicators: List<TeeEvidenceItem>,
    nativeProbesAvailable: Boolean,
): String = when (verdict) {
    TeeVerdict.CONSISTENT -> when {
        supplementaryIndicators.isNotEmpty() -> "Aligned • local review"
        !nativeProbesAvailable -> "Aligned • native unavailable"
        else -> "Checks aligned"
    }

    TeeVerdict.TAMPERED -> "${policyHardIndicators.size} policy anomaly"
    TeeVerdict.SUSPICIOUS -> "${policySoftIndicators.size} policy review"
    TeeVerdict.BROKEN -> "No hardware trust"
    TeeVerdict.INCONCLUSIVE -> "Mixed signals"
    TeeVerdict.LOADING -> "Scanning"
}

internal fun trustSummaryFor(artifacts: TeeScanArtifacts): String {
    return buildString {
        append("Local trust path: ")
        append(trustRootLabel(normalizeTrustRoot(artifacts.trust.trustRoot)))
        append(", chain ")
        append(if (artifacts.trust.chainSignatureValid) "verified" else "failed")
        if (artifacts.rkp.provisioned) {
            append(", ")
            append(
                when {
                    !artifacts.trust.chainSignatureValid -> "RKP observed on an invalid local chain"
                    hasLocalTrustReviewSignals(artifacts) -> "RKP observed, local trust needs review"
                    else -> "RKP observed"
                }
            )
        } else if (artifacts.rkp.consistencyIssue != null) {
            append(", provisioning needs review")
        }
    }
}

internal fun fact(
    title: String,
    body: String,
    level: TeeSignalLevel,
    hiddenCopyText: String? = null,
    grant: TeeGrantEvidence? = null,
    topic: TeeEvidenceTopic? = null,
): TeeEvidenceItem = TeeEvidenceItem(
    title = title,
    body = body,
    level = level,
    hiddenCopyText = hiddenCopyText,
    grant = grant,
    topic = topic,
)
