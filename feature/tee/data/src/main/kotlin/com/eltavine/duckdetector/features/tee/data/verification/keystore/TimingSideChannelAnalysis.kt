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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import java.util.Locale
import kotlin.math.roundToInt

internal data class StableTimeSource(
    private val preferRegisterTimer: Boolean,
    private val registerTimerSource: () -> Long?,
    private val monotonicSource: () -> Long,
) {
    fun readNs(): Long = stableTimerReadNs(preferRegisterTimer, registerTimerSource, monotonicSource)
}

internal fun stableTimerReadNs(
    preferRegisterTimer: Boolean,
    registerTimerSource: () -> Long?,
    monotonicSource: () -> Long,
): Long {
    if (preferRegisterTimer) {
        return registerTimerSource() ?: throw IllegalStateException(
            "Register timer read failed while arm64_cntvct was selected as the preferred timing source.",
        )
    }
    return monotonicSource()
}

internal fun isPositiveTimingSideChannelRatio(
    avgAttestedMillis: Double?,
    avgNonAttestedMillis: Double?,
): Boolean {
    val ratio = timingSideChannelRatio(avgAttestedMillis, avgNonAttestedMillis) ?: return false
    return ratio > TIMING_SIDE_CHANNEL_THRESHOLD_RATIO
}

internal fun isTimingSideChannelRatioEligible(sampleCount: Int): Boolean {
    return sampleCount >= MIN_RATIO_SAMPLE_COUNT
}

internal fun timingSideChannelRatio(
    avgAttestedMillis: Double?,
    avgNonAttestedMillis: Double?,
): Double? {
    val attested = avgAttestedMillis ?: return null
    val nonAttested = avgNonAttestedMillis ?: return null
    if (
        attested <= 0.0 ||
        nonAttested <= 0.0 ||
        attested.isNaN() ||
        nonAttested.isNaN() ||
        attested.isInfinite() ||
        nonAttested.isInfinite()
    ) {
        return null
    }
    val high = maxOf(attested, nonAttested)
    val low = minOf(attested, nonAttested)
    return high / low
}

internal fun buildTimingSideChannelDetail(
    source: String,
    timerSource: String,
    affinity: String,
    avgAttestedMillis: Double?,
    avgNonAttestedMillis: Double?,
    diffMillis: Double?,
    suspicious: Boolean,
    sampleCount: Int,
    warmupCount: Int,
    measurementDetail: String,
    timerFallbackReason: String?,
    partialFailureReason: String?,
): String {
    return buildString {
        val ratio = timingSideChannelRatio(avgAttestedMillis, avgNonAttestedMillis)
        append("semantics=service.getKeyEntry")
        append(", source=")
        append(source)
        append(", timer=")
        append(timerSource)
        append(", affinity=")
        append(affinity)
        append(", avgAttested=")
        append(avgAttestedMillis?.let { String.format(Locale.US, "%.3f", it) } ?: "n/a")
        append("ms, avgNonAttested=")
        append(avgNonAttestedMillis?.let { String.format(Locale.US, "%.3f", it) } ?: "n/a")
        append("ms, diff=")
        append(diffMillis?.let { String.format(Locale.US, "%.3f", it) } ?: "n/a")
        append("ms, suspicious=")
        append(suspicious)
        append(", ratio=")
        append(ratio?.let { String.format(Locale.US, "%.3f", it) } ?: "n/a")
        append(", threshold=ratio > ")
        append(String.format(Locale.US, "%.1f", TIMING_SIDE_CHANNEL_THRESHOLD_RATIO))
        append(", warmup=")
        append(warmupCount)
        append(", samples=")
        append(sampleCount)
        append(". ")
        append(measurementDetail)
        timerFallbackReason?.let {
            append(" timerFallback=")
            append(it)
        }
        partialFailureReason?.let {
            append(" partialFailure=")
            append(it)
        }
    }
}

internal fun selectTimingSideChannelCopyPayload(
    warmupFailures: List<CapturedThrowableRecord>,
    gatewayFailures: List<CapturedThrowableRecord>,
): String {
    // 复制入口优先给 warmup 失败，因为这部分最贴近 skip 语义；gateway 栈只作为“warmup 没抓到但会话内部确实报错了”的兜底证据。
    // Prefer warmup failures for copy because they best explain skip semantics; gateway failures are the fallback evidence when warmup stayed silent.
    val selected = if (warmupFailures.isNotEmpty()) warmupFailures else gatewayFailures
    if (selected.isEmpty()) {
        return "null"
    }
    return selected.joinToString(separator = "\n\n---\n\n") { record ->
        buildString {
            append("phase=")
            append(record.phase)
            append('\n')
            append("summary=")
            append(record.summary)
            append('\n')
            append("occurrences=")
            append(record.occurrenceCount)
            append("\n\n")
            append(record.stackTrace)
        }
    }
}

internal fun pairedDiffSeries(
    attestedSamples: List<Double>,
    nonAttestedSamples: List<Double>,
): List<Double> {
    val pairedCount = minOf(attestedSamples.size, nonAttestedSamples.size)
    return buildList(pairedCount) {
        repeat(pairedCount) { index ->
            add(attestedSamples[index] - nonAttestedSamples[index])
        }
    }
}

data class TimingSideChannelResult(
    val probeRan: Boolean,
    val measurementAvailable: Boolean = false,
    val suspicious: Boolean = false,
    val sampleCount: Int = 0,
    val attemptedPairCount: Int = 0,
    val successfulPairCount: Int = 0,
    val failedPairCount: Int = 0,
    val filteredOutlierCount: Int = 0,
    val ratioEligible: Boolean = true,
    val ratioSkipReason: String? = null,
    val warmupCount: Int = 0,
    val avgAttestedMillis: Double? = null,
    val avgNonAttestedMillis: Double? = null,
    val diffMillis: Double? = null,
    val source: String = "unknown",
    val timerSource: String = "unknown",
    val affinity: String = "unknown",
    val fallback: List<String> = emptyList(),
    val failureReason: String? = null,
    // 这里保存的是给人工静态审查用的原始异常 payload，不参与阈值计算，但会驱动 skip->patch-mode 的静态签名判定。
    // This stores the raw exception payload for human/static review; it does not affect timing math directly, but it does drive skip-to-patch-mode signature matching.
    val stackCopyPayload: String = "null",
    /**
     * Whether the device advertises app attestation keys (PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY).
     * The probe provisions a PURPOSE_ATTEST_KEY key, so without the feature a binder error is expected.
     */
    val appAttestKeyAdvertised: Boolean = false,
    val detail: String,
) {
    fun avgAttestedMicros(): Int? = avgAttestedMillis?.times(1_000)?.roundToInt()

    fun avgNonAttestedMicros(): Int? = avgNonAttestedMillis?.times(1_000)?.roundToInt()

    fun diffMicros(): Int? = diffMillis?.times(1_000)?.roundToInt()
}

// 阈值故意保持单点常量，避免 probe/reducer/test 三处漂移。 / Keep the threshold as a single source of truth so probe, reducer, and tests cannot drift.
internal const val TIMING_SIDE_CHANNEL_THRESHOLD_RATIO = 1.1

internal const val MIN_RATIO_SAMPLE_COUNT = 300
