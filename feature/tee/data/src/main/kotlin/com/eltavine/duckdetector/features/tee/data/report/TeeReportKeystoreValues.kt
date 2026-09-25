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

import com.eltavine.duckdetector.features.tee.data.verification.keystore.AesGcmRoundTripResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.MIN_RATIO_SAMPLE_COUNT
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TIMING_SIDE_CHANNEL_THRESHOLD_RATIO
import com.eltavine.duckdetector.features.tee.data.verification.keystore.timingSideChannelRatio
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import java.util.Locale

internal fun keyPairValue(artifacts: TeeScanArtifacts): String {
    val base = if (artifacts.pairConsistency.keyMatchesCertificate) {
        "Signature matched certificate"
    } else {
        "Public key mismatch"
    }
    return artifacts.pairConsistency.medianSignMicros?.let { "$base • ${it}us" } ?: base
}

internal fun lifecycleValue(artifacts: TeeScanArtifacts): String {
    return when {
        artifacts.lifecycle.deleteRemovedAlias && artifacts.lifecycle.regeneratedFreshMaterial -> "Delete ok • fresh material"
        else -> "Delete/regenerate contradiction"
    }
}

internal fun aesGcmValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.aesGcm
    val authorizationFailures = aesGcmAuthorizationFailures(result)
    return when {
        !result.executed -> result.probeError?.let { "Did not complete • $it" } ?: "Skipped"
        !result.roundTripSucceeded -> buildString {
            append("Round-trip failed")
            result.keyInfoLevel?.let {
                append(" • ")
                append(it)
            }
        }

        authorizationFailures.isNotEmpty() -> buildString {
            append("Auth failed")
            append(" • ")
            append(authorizationFailures.joinToString("; "))
        }

        result.insideSecureHardware == true -> buildString {
            append("Round-trip ok")
            result.keyInfoLevel?.let {
                append(" • ")
                append(it)
            }
            result.encryptMicros?.let {
                append(" • ")
                append(it)
                append("us enc")
            }
            appendAuthorizationNotChecked(result)
        }

        else -> buildString {
            append("Round-trip ok • software-backed")
            result.keyInfoLevel?.let {
                append(" • ")
                append(it)
            }
            appendAuthorizationNotChecked(result)
        }
    }
}

private fun StringBuilder.appendAuthorizationNotChecked(result: AesGcmRoundTripResult) {
    if (!result.authorizationChecked) append(" • authorization checks did not run")
}

internal fun aesGcmAuthorizationFailures(result: AesGcmRoundTripResult): List<String> {
    if (!result.executed) {
        return emptyList()
    }
    return buildList {
        if (!result.cbcRejected) add("CBC: ${result.cbcRejectedDetail}")
        if (!result.mac64Rejected) add("MAC64: ${result.mac64RejectedDetail}")
        if (!result.shortNonceRejected) add("nonce: ${result.shortNonceRejectedDetail}")
    }
}

internal fun keyMintCryptoValue(artifacts: TeeScanArtifacts): String {
    if (!artifacts.keyMintCapability.executed) {
        return "Skipped"
    }
    return keyMintCryptoChecks(artifacts).joinToString(" • ") { check ->
        when {
            !check.executed -> "${check.name} skipped"
            check.ok -> "${check.name} ok"
            else -> "${check.name} failed: ${check.detail}"
        }
    }
}

internal fun keyMintCryptoDiagnosticCopyText(artifacts: TeeScanArtifacts): String = buildString {
    appendLine("tee-keymint-crypto-diagnostic=v1")
    appendLine("tier=${effectiveTier(artifacts)}")
    appendLine("attestationTier=${artifacts.snapshot.attestationTier ?: "null"}")
    appendLine("keymasterTier=${artifacts.snapshot.keymasterTier ?: "null"}")
    appendLine("attestationVersion=${artifacts.snapshot.attestationVersion ?: "null"}")
    appendLine("keymasterVersion=${artifacts.snapshot.keymasterVersion ?: "null"}")
    appendLine("vintfKind=${artifacts.vintfKeyMintVersion.anomalyKind}")
    appendLine(
        "vintfCompared=" + artifacts.vintfKeyMintVersion.comparedDeclarations
            .joinToString { it.summary }
            .ifBlank { "none" },
    )
    appendLine("vintfDiagnostic:")
    artifacts.vintfKeyMintVersion.diagnosticCopyText.lineSequence().forEach { line ->
        appendLine("  $line")
    }
    appendLine("capabilityExecuted=${artifacts.keyMintCapability.executed}")
    append(artifacts.keyMintCapability.diagnosticCopyText.ifBlank { "probeDiagnostic=unavailable" })
}

internal fun keyMintCryptoLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    !artifacts.keyMintCapability.executed -> TeeSignalLevel.INFO
    keyMintCryptoFailures(artifacts).isNotEmpty() -> TeeSignalLevel.FAIL
    keyMintCryptoChecks(artifacts).any { !it.executed } -> TeeSignalLevel.INFO
    else -> TeeSignalLevel.PASS
}

internal fun keyMintCryptoFailures(artifacts: TeeScanArtifacts): List<String> {
    if (!artifacts.keyMintCapability.executed) {
        return emptyList()
    }
    return keyMintCryptoChecks(artifacts)
        .filter { it.executed && !it.ok }
        .map { "${it.name}: ${it.detail}" }
}

private fun keyMintCryptoChecks(artifacts: TeeScanArtifacts): List<KeyMintCryptoCheck> {
    val crypto = artifacts.keyMintCapability.crypto
    return listOf(
        KeyMintCryptoCheck("HMAC-SHA256", true, crypto.hmacSha256Ok, crypto.hmacSha256Detail),
        KeyMintCryptoCheck(
            "Single-use EC",
            crypto.limitedUseEcExecuted,
            crypto.limitedUseEcOk,
            crypto.limitedUseEcDetail,
        ),
        KeyMintCryptoCheck("ECDH P-256", crypto.ecdhP256Executed, crypto.ecdhP256Ok, crypto.ecdhP256Detail),
        KeyMintCryptoCheck("RSA-PSS SHA-256", true, crypto.rsaPssSha256Ok, crypto.rsaPssSha256Detail),
        KeyMintCryptoCheck("AES-CBC/CTR auth", crypto.aesCbcCtrExecuted, crypto.aesCbcCtrOk, crypto.aesCbcCtrDetail),
        KeyMintCryptoCheck(
            "AES-CBC padding auth",
            crypto.aesCbcNoPaddingExecuted,
            crypto.aesCbcNoPaddingOk,
            crypto.aesCbcNoPaddingDetail,
        ),
        KeyMintCryptoCheck("EC SHA-512 auth", crypto.ecSha512Executed, crypto.ecSha512Ok, crypto.ecSha512Detail),
        KeyMintCryptoCheck(
            "RSA-PSS SHA-512 auth",
            crypto.rsaPssSha512Executed,
            crypto.rsaPssSha512Ok,
            crypto.rsaPssSha512Detail,
        ),
        KeyMintCryptoCheck(
            "RSA-PSS PKCS#1 auth",
            crypto.rsaPssPkcs1Executed,
            crypto.rsaPssPkcs1Ok,
            crypto.rsaPssPkcs1Detail,
        ),
        KeyMintCryptoCheck(
            "RSA OAEP/PKCS#1 auth",
            crypto.rsaOaepPkcs1Executed,
            crypto.rsaOaepPkcs1Ok,
            crypto.rsaOaepPkcs1Detail,
        ),
        KeyMintCryptoCheck(
            "RSA PKCS#1/OAEP auth",
            crypto.rsaPkcs1OaepExecuted,
            crypto.rsaPkcs1OaepOk,
            crypto.rsaPkcs1OaepDetail,
        ),
        KeyMintCryptoCheck(
            "RSA-OAEP MGF1",
            crypto.rsaOaepMgf1Executed,
            crypto.rsaOaepMgf1Ok,
            crypto.rsaOaepMgf1Detail,
        ),
        KeyMintCryptoCheck(
            "RSA-OAEP MGF1 auth",
            crypto.rsaOaepMgf1Sha1Executed,
            crypto.rsaOaepMgf1Sha1Ok,
            crypto.rsaOaepMgf1Sha1Detail,
        ),
        KeyMintCryptoCheck(
            "RSA-OAEP SHA-256",
            crypto.rsaOaepSha256Executed,
            crypto.rsaOaepSha256Ok,
            crypto.rsaOaepSha256Detail,
        ),
        KeyMintCryptoCheck(
            "RSA-OAEP SHA-1 auth",
            crypto.rsaOaepSha1Executed,
            crypto.rsaOaepSha1Ok,
            crypto.rsaOaepSha1Detail,
        ),
        KeyMintCryptoCheck("EC NONE auth", crypto.ecNoneExecuted, crypto.ecNoneOk, crypto.ecNoneDetail),
        KeyMintCryptoCheck(
            "RSA PKCS#1 SHA-1 auth",
            crypto.rsaPkcs1Sha1Executed,
            crypto.rsaPkcs1Sha1Ok,
            crypto.rsaPkcs1Sha1Detail,
        ),
        KeyMintCryptoCheck(
            "RSA PKCS#1/PSS auth",
            crypto.rsaPkcs1PssExecuted,
            crypto.rsaPkcs1PssOk,
            crypto.rsaPkcs1PssDetail,
        ),
    )
}

internal data class KeyMintCryptoCheck(
    val name: String,
    val executed: Boolean,
    val ok: Boolean,
    val detail: String,
)

internal fun timingValue(artifacts: TeeScanArtifacts): String {
    val median = artifacts.timing.medianMicros?.let { "${it}us" } ?: "n/a"
    return if (artifacts.timing.suspicious) {
        "Fast/steady • $median"
    } else {
        "Median $median"
    }
}

internal fun timingSideChannelValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.timingSideChannel
    val skipSignature = timingSideChannelSkipSignature(result)
    val timerSource = timingSideChannelTimerSourceLabel(result.timerSource, result.detail)
    val thresholdRatio = String.format(Locale.US, "%.1fx", TIMING_SIDE_CHANNEL_THRESHOLD_RATIO)
    val ratio = timingSideChannelRatio(result.avgAttestedMillis, result.avgNonAttestedMillis)
    val ratioLabel = when {
        result.measurementAvailable && !result.ratioEligible -> "skipped"
        else -> ratio?.let { String.format(Locale.US, "%.3fx", it) } ?: "n/a"
    }
    val affinity = when {
        result.affinity.isBlank() || result.affinity == "unknown" -> "affinity unknown"
        else -> result.affinity
    }
    if (skipSignature != null) {
        // skip 命中 patch signature 时，row 文案直接切到 patch-mode，可视层不再展示“measurement unavailable”这种弱语义。
        // When skip hits a patch signature, switch the row text directly to patch-mode wording instead of weaker "measurement unavailable" phrasing.
        return listOf(skipSignature.rowLabel, timerSource, affinity)
            .filter { it.isNotBlank() }
            .joinToString(separator = " • ")
    }
    val avgAttested = result.avgAttestedMillis?.let { String.format(Locale.US, "%.3fms", it) } ?: "n/a"
    val avgNonAttested = result.avgNonAttestedMillis?.let { String.format(Locale.US, "%.3fms", it) } ?: "n/a"
    val diff = result.diffMillis?.let { String.format(Locale.US, "%.3fms", it) } ?: "n/a"
    val state = when {
        !result.probeRan -> "Skipped"
        !result.measurementAvailable -> "Measurement unavailable"
        !result.ratioEligible -> "Ratio skipped"
        result.suspicious -> "Positive"
        else -> "Not positive"
    }
    val attemptedPairs = result.attemptedPairCount.takeIf { it > 0 } ?: result.sampleCount
    val successfulPairs = result.successfulPairCount.takeIf { it > 0 } ?: result.sampleCount
    val failedPairs = " • failedPairs=${result.failedPairCount}/$attemptedPairs"
    val outlierFiltered = " • outlierFiltered=${result.filteredOutlierCount}/$successfulPairs"
    val samples = " • samples=${result.sampleCount}"
    val ratioSkip = result.ratioSkipReason?.takeIf { it.isNotBlank() }?.let { " • $it" }.orEmpty()
    val reason = result.failureReason?.takeIf { it.isNotBlank() }?.let { " • reason $it" }.orEmpty()
    return "$timerSource • $affinity • attested $avgAttested • non-attested $avgNonAttested • diff $diff • ratio $ratioLabel • threshold > $thresholdRatio$failedPairs$outlierFiltered$samples$ratioSkip • $state$reason"
}

internal fun timingSideChannelSummary(artifacts: TeeScanArtifacts): String {
    val result = artifacts.timingSideChannel
    timingSideChannelSkipSignature(result)?.let { return it.summary }
    val timerSource = timingSideChannelTimerSourceLabel(result.timerSource, result.detail)
    val thresholdRatio = String.format(Locale.US, "%.1fx", TIMING_SIDE_CHANNEL_THRESHOLD_RATIO)
    if (!result.measurementAvailable) {
        return "$timerSource timing side-channel could not finish measurement; ${result.failureReason ?: "reason unavailable"}."
    }
    if (!result.ratioEligible) {
        return "$timerSource timing side-channel skipped ratio; ${result.ratioSkipReason ?: "insufficientSamples=${result.sampleCount}/$MIN_RATIO_SAMPLE_COUNT"}."
    }
    val ratio = timingSideChannelRatio(result.avgAttestedMillis, result.avgNonAttestedMillis)
    val thresholdDirection = ratio?.let { value ->
        val ratioText = String.format(Locale.US, "%.2fx", value)
        if (value > TIMING_SIDE_CHANNEL_THRESHOLD_RATIO) {
            "ratio $ratioText exceeded $thresholdRatio"
        } else {
            "ratio $ratioText stayed within $thresholdRatio"
        }
    } ?: "ratio unavailable"
    return "$timerSource timing side-channel stayed supplementary; $thresholdDirection."
}

private fun timingSideChannelTimerSourceLabel(timerSource: String, detail: String): String {
    val normalized = timerSource.lowercase(Locale.US)
    val lowered = detail.lowercase(Locale.US)
    return when {
        "cntvct" in normalized || "register" in normalized -> "Register timer"
        "monotonic" in normalized || "nano" in normalized -> "Fallback timer"
        "register" in lowered -> "Register timer"
        "fallback" in lowered -> "Fallback timer"
        else -> "Timer source unspecified"
    }
}

internal fun keyboxValue(artifacts: TeeScanArtifacts): String {
    return when {
        !artifacts.keyboxImport.executed -> "Skipped"
        artifacts.keyboxImport.markerPreserved -> "Marker preserved"
        else -> "Marker replaced"
    }
}

internal fun importKeyRetainedAttestationNarrativeValue(artifacts: TeeScanArtifacts): String {
    val result = artifacts.importKeyRetainedAttestationNarrative
    // Keep the stable anomaly kind in the Checks row: the TEE card mapper uses it to propagate red-card state to the dashboard without exposing raw DER.
    // 保留稳定 anomaly kind 在 Checks 行里：TEE card mapper 依赖它把红卡状态上传到 Dashboard，同时不暴露原始 DER。
    val status = when {
        result.anomalyKind == com.eltavine.duckdetector.features.tee.data.verification.keystore.ImportKeyRetainedAttestationAnomalyKind.IMPORT_UNSUPPORTED -> "Unavailable"
        !result.executed -> "Unavailable"
        result.retainedNarrativeDetected -> "Matched"
        result.importSupported && result.markerImportBaselineClean -> "Clean"
        else -> "Unavailable"
    }
    val detail = result.detail.takeIf { it.isNotBlank() } ?: return status
    return "$status • $detail"
}

internal fun oversizedChallengeValue(artifacts: TeeScanArtifacts): String {
    return if (artifacts.oversizedChallenge.acceptedOversizedChallenge) {
        "Accepted ${artifacts.oversizedChallenge.acceptedSizesLabel()}"
    } else {
        "Rejected ${artifacts.oversizedChallenge.attemptedSizesLabel()}"
    }
}

internal fun generateModeAnomalyValue(artifacts: TeeScanArtifacts): String {
    return when (generateModeAnomalyState(artifacts)) {
        GenerateModeAnomalyState.MATCHED ->
            "Matched TEE Simulator generate-mode fingerprint."

        GenerateModeAnomalyState.CLEAN ->
            "No TEE Simulator generate-mode fingerprint observed."

        GenerateModeAnomalyState.UNAVAILABLE -> "TEE Simulator generate-mode fingerprint probe unavailable."
    }
}

internal fun keystore2Value(artifacts: TeeScanArtifacts): String {
    return when {
        artifacts.keystore2Hook.javaHookDetected -> "Java-style reply"
        artifacts.keystore2Hook.nativeStyleResponse -> "Native-style reply"
        !artifacts.keystore2Hook.available -> "Unavailable"
        else -> artifacts.keystore2Hook.errorCode?.let { "Error $it" } ?: "Unexpected reply"
    }
}
