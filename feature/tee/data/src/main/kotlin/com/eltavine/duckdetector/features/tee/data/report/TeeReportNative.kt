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

import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import java.util.Locale

internal fun nativeValue(artifacts: TeeScanArtifacts): String {
    return when {
        artifacts.native.trickyStoreDetected -> buildString {
            append(nativeMethodSummary(artifacts))
            append(" • ")
            append(artifacts.native.trickyStoreTimerSource)
            append(" • ")
            append(artifacts.native.trickyStoreAffinityStatus)
            nativeTimingStatsSummary(artifacts)?.let {
                append('\n')
                append(it)
            }
            artifacts.native.trickyStoreDetails
                .takeUnless { it == "Native probe unavailable" }
                ?.takeIf { it.isNotBlank() }
                ?.let {
                    append('\n')
                    append(it)
                }
        }
        artifacts.native.trickyStoreDetails != "Native probe unavailable" &&
            !hasNativeReviewSignals(artifacts) &&
            !artifacts.native.leafDerPrimaryDetected -> buildString {
            append(artifacts.native.trickyStoreDetails)
            nativeTimingStatsSummary(artifacts)?.let {
                append("\n")
                append(it)
            }
            if (artifacts.native.trickyStoreTimerSource != "unknown") {
                append("\n")
                append(artifacts.native.trickyStoreTimerSource)
                append(" • ")
                append(artifacts.native.trickyStoreAffinityStatus)
            }
        }
        artifacts.native.leafDerPrimaryDetected -> "Primary DER hit"
        hasNativeReviewSignals(artifacts) -> buildString {
            append(nativeReviewSummary(artifacts))
            if (artifacts.native.syscallMismatchDetected) {
                append('\n')
                append(syscallMismatchExplanation())
            }
        }

        else -> "No local process-side anomaly"
    }
}

private fun nativeTimingStatsSummary(artifacts: TeeScanArtifacts): String? {
    return buildList {
        val suspiciousRuns = artifacts.native.trickyStoreTimingSuspiciousRunCount
        val totalRuns = artifacts.native.trickyStoreTimingRunCount
        if (suspiciousRuns != null && totalRuns != null && totalRuns > 0) {
            add("$suspiciousRuns/$totalRuns suspicious runs")
        }
        artifacts.native.trickyStoreTimingMedianGapNs
            ?.takeIf { it > 0L }
            ?.let { add("median gap ${formatNanoseconds(it)}") }
        artifacts.native.trickyStoreTimingGapMadNs
            ?.takeIf { it > 0L }
            ?.let { add("gap MAD ${formatNanoseconds(it)}") }
        artifacts.native.trickyStoreTimingMedianNoiseFloorNs
            ?.takeIf { it > 0L }
            ?.let { add("noise floor ${formatNanoseconds(it)}") }
        artifacts.native.trickyStoreTimingMedianRatioPercent
            ?.takeIf { it > 0 }
            ?.let { add("median ratio ${formatRatioPercent(it)}") }
    }.takeIf { it.isNotEmpty() }?.joinToString(separator = " • ")
}

private fun formatNanoseconds(valueNs: Long): String {
    return when {
        valueNs >= 1_000_000L -> String.format(Locale.US, "%.2fms", valueNs / 1_000_000.0)
        valueNs >= 100L -> String.format(Locale.US, "%.1fus", valueNs / 1_000.0)
        else -> "${valueNs}ns"
    }
}

private fun formatRatioPercent(percent: Int): String {
    return String.format(Locale.US, "%.2fx", percent / 100.0)
}

internal fun nativeSignalValue(artifacts: TeeScanArtifacts): String = when {
    artifacts.native.trickyStoreDetected -> nativePrimarySignalLabel(artifacts)
    artifacts.native.leafDerPrimaryDetected -> "Primary DER"
    artifacts.native.leafDerSecondaryDetected -> "Secondary DER"
    artifacts.native.tracingDetected -> "Tracing"
    artifacts.native.suspiciousMappings.isNotEmpty() -> "Mappings"
    artifacts.native.syscallMismatchDetected -> "Syscall mismatch"
    else -> "Review"
}

internal fun nativeSignalLevel(artifacts: TeeScanArtifacts): TeeSignalLevel = when {
    artifacts.native.trickyStoreDetected || artifacts.native.leafDerPrimaryDetected -> TeeSignalLevel.FAIL
    artifacts.native.leafDerSecondaryDetected || artifacts.native.tracingDetected || artifacts.native.suspiciousMappings.isNotEmpty() -> TeeSignalLevel.WARN
    artifacts.native.syscallMismatchDetected -> TeeSignalLevel.INFO
    else -> TeeSignalLevel.INFO
}

private fun hasNativeReviewSignals(artifacts: TeeScanArtifacts): Boolean {
    return artifacts.native.syscallMismatchDetected ||
            artifacts.native.leafDerSecondaryDetected ||
            artifacts.native.tracingDetected ||
            artifacts.native.suspiciousMappings.isNotEmpty()
}

private fun nativeReviewSummary(artifacts: TeeScanArtifacts): String {
    return buildList {
        if (artifacts.native.syscallMismatchDetected) add("Syscall mismatch")
        if (artifacts.native.leafDerSecondaryDetected) add("Secondary DER hit")
        if (artifacts.native.tracingDetected) add("Tracing active")
        if (artifacts.native.suspiciousMappings.isNotEmpty()) {
            add("${artifacts.native.suspiciousMappings.size} suspicious mapping(s)")
        }
    }.joinToString(separator = " • ")
}

internal fun nativeMethodSummary(artifacts: TeeScanArtifacts): String {
    val labels = artifacts.native.trickyStoreMethods
        .map(::prettyNativeMethod)
        .ifEmpty {
            buildList {
                if (artifacts.native.gotHookDetected) add("GOT hook")
                if (artifacts.native.inlineHookDetected) add("Inline hook")
                if (artifacts.native.honeypotDetected) add("Honeypot")
                if (artifacts.native.syscallMismatchDetected) add("Syscall mismatch")
            }
        }
    return labels.ifEmpty { listOf("TrickyStore") }.joinToString(separator = " • ")
}

private fun nativePrimarySignalLabel(artifacts: TeeScanArtifacts): String {
    return when {
        artifacts.native.gotHookDetected -> "GOT hook"
        artifacts.native.inlineHookDetected -> "Inline hook"
        artifacts.native.honeypotDetected -> "Honeypot"
        else -> nativeMethodSummary(artifacts)
    }
}

private fun prettyNativeMethod(method: String): String = when (method) {
    "MAPS_NAME_HIT" -> "Map hit"
    "GOT_HOOK" -> "GOT hook"
    "INLINE_HOOK" -> "Inline hook"
    "HONEYPOT" -> "Honeypot"
    "SYSCALL_MISMATCH" -> "Syscall mismatch"
    else -> method.replace('_', ' ').lowercase()
}

private fun syscallMismatchExplanation(): String {
    return "Possible cause: vendor binder/libc compatibility differences. No stronger hook fingerprint was found."
}
