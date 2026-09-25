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

import com.eltavine.duckdetector.features.tee.data.native.NativeTeeSnapshot
import com.eltavine.duckdetector.features.tee.data.native.TeeRegisterTimerNativeBridge
import android.os.SystemClock

/**
 * 在同一组私有 binder 代理语义下对 attested / non-attested key 做配对测量，保证 timing 差值和 skip 栈都来自同一条隐藏接口路径。
 * Measures attested / non-attested keys under the same private binder proxy semantics so both timing deltas and skip stacks come from one hidden-interface path.
 */
class TimingSideChannelProbe(
    private val registerTimerBridge: TeeRegisterTimerNativeBridge = TeeRegisterTimerNativeBridge(),
    private val binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
) {

    fun inspect(
        useStrongBox: Boolean = false,
        nativeSnapshot: NativeTeeSnapshot = NativeTeeSnapshot(),
    ): TimingSideChannelResult {
        val initialTimerMetadata = resolveTimerMetadata(nativeSnapshot)
        val measurementContext = bindMeasurementContext(initialTimerMetadata)
        val warmupFailures = CapturedThrowableCollector()
        var gatewayFailures = emptyList<CapturedThrowableRecord>()
        val fallback = mutableListOf<String>().apply {
            initialTimerMetadata.timerFallbackReason?.let { add(it) }
            if (
                measurementContext.timerFallbackReason != null &&
                measurementContext.timerFallbackReason != initialTimerMetadata.timerFallbackReason
            ) {
                add(measurementContext.timerFallbackReason)
            }
        }
        fun describeFailure(throwable: Throwable): String = binderClient.describeThrowable(throwable)

        val result = runCatching {
            val sessionResult = binderClient.openSession(useStrongBox = useStrongBox)
            gatewayFailures = sessionResult.capturedFailures
            val session = sessionResult.session
                ?: throw IllegalStateException(
                    sessionResult.failureReason
                        ?: "Keystore2 private binder proxy session unavailable."
                )
            val aliases = binderClient.createTimingAliases()
            val attestedDescriptor = binderClient.createKeyDescriptor(aliases.attestedAlias)
            val nonAttestedDescriptor = binderClient.createKeyDescriptor(aliases.nonAttestedAlias)
            val attestKeyDescriptor = binderClient.createKeyDescriptor(aliases.attestKeyAlias)
            val warnings = mutableListOf<String>()
            var partialFailureReason: String? = null
            var effectiveAttestedDescriptor = attestedDescriptor
            var effectiveNonAttestedDescriptor = nonAttestedDescriptor
            var effectiveAttestKeyDescriptor = attestKeyDescriptor

            try {
                // 生成阶段一旦返回 KEY_ID 风格 descriptor，后续 warmup/sample/delete 都必须切到 follow-up descriptor，保证测的是同一个真实 key handle。
                // Once generateKey returns a KEY_ID-style descriptor, every warmup/sample/delete step must switch to that follow-up descriptor to stay on the same real key handle.
                val attestationKeyMetadata = binderClient.generateAttestationKey(
                    session.securityLevel,
                    attestKeyDescriptor,
                )
                effectiveAttestKeyDescriptor = binderClient.resolveFollowUpDescriptor(
                    requestedDescriptor = attestKeyDescriptor,
                    keyMetadataOrResponse = attestationKeyMetadata,
                )
                val attestedKeyMetadata = binderClient.generateSigningKey(
                    securityLevel = session.securityLevel,
                    keyDescriptor = attestedDescriptor,
                    attestationKeyDescriptor = effectiveAttestKeyDescriptor,
                    attest = true,
                )
                effectiveAttestedDescriptor = binderClient.resolveFollowUpDescriptor(
                    requestedDescriptor = attestedDescriptor,
                    keyMetadataOrResponse = attestedKeyMetadata,
                )
                val nonAttestedKeyMetadata = binderClient.generateSigningKey(
                    securityLevel = session.securityLevel,
                    keyDescriptor = nonAttestedDescriptor,
                    attestationKeyDescriptor = null,
                    attest = false,
                )
                effectiveNonAttestedDescriptor = binderClient.resolveFollowUpDescriptor(
                    requestedDescriptor = nonAttestedDescriptor,
                    keyMetadataOrResponse = nonAttestedKeyMetadata,
                )

                val measurement = Measurement(
                    source = "keystore2_security_level_proxy",
                    detail = "Measured service.getKeyEntry timing on a TEE-only private binder proxy path; serviceProxy=${session.serviceProxyActive}, securityLevelProxy=${session.securityLevelProxyActive}, proxyInstalled=${session.proxyInstalled}",
                    measureMillis = { descriptor, timer -> measurePrivateGetKeyEntryMillis(session.service, descriptor, timer) },
                    timerSource = measurementContext.timeSource,
                )

                // warmup 的栈最接近真实“样本为何无法测量”的原因；只有 warmup 没留下东西时，才退回整条私有代理链路的诊断栈。
                // Warmup stacks best represent why the measurement could not start; only when warmup captures nothing do we fall back to session-wide proxy diagnostics.
                warmUpPair(
                    measurement = measurement,
                    attestedDescriptor = effectiveAttestedDescriptor,
                    nonAttestedDescriptor = effectiveNonAttestedDescriptor,
                    warnings = warnings,
                    warmupFailures = warmupFailures,
                    describeFailure = ::describeFailure,
                )
                val pairedSeries = samplePairedSeries(
                    measurement = measurement,
                    attestedDescriptor = effectiveAttestedDescriptor,
                    nonAttestedDescriptor = effectiveNonAttestedDescriptor,
                    warnings = warnings,
                    describeFailure = ::describeFailure,
                )
                val filteredSeries = pairedSeries.filterOutlierPairs()
                check(pairedSeries.attestedSamples.isNotEmpty() && pairedSeries.nonAttestedSamples.isNotEmpty()) {
                    "Timing side-channel measurement produced no samples"
                }
                partialFailureReason = listOfNotNull(pairedSeries.failureReason)
                    .joinToString("; ")
                    .takeIf { it.isNotBlank() }

                val avgAttested = filteredSeries.attestedSamples.averageOrNull()
                val avgNonAttested = filteredSeries.nonAttestedSamples.averageOrNull()
                val diff = if (avgAttested != null && avgNonAttested != null) avgAttested - avgNonAttested else null
                val ratioEligible = isTimingSideChannelRatioEligible(filteredSeries.pairedSampleCount)
                val ratioSkipReason = if (ratioEligible) {
                    null
                } else {
                    "insufficientSamples=${filteredSeries.pairedSampleCount}/$MIN_RATIO_SAMPLE_COUNT"
                }
                val suspicious = ratioEligible && isPositiveTimingSideChannelRatio(avgAttested, avgNonAttested)
                val filteredOutlierCount = pairedSeries.pairedSampleCount - filteredSeries.pairedSampleCount
                val samplingNotes = buildList {
                    add("failedPairs=${pairedSeries.failedPairCount}/${pairedSeries.attemptedPairCount}")
                    add("outlierFiltered=$filteredOutlierCount/${pairedSeries.pairedSampleCount}")
                    ratioSkipReason?.let(::add)
                }

                TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = true,
                    suspicious = suspicious,
                    sampleCount = filteredSeries.pairedSampleCount,
                    attemptedPairCount = pairedSeries.attemptedPairCount,
                    successfulPairCount = pairedSeries.pairedSampleCount,
                    failedPairCount = pairedSeries.failedPairCount,
                    filteredOutlierCount = filteredOutlierCount,
                    ratioEligible = ratioEligible,
                    ratioSkipReason = ratioSkipReason,
                    warmupCount = WARMUP_COUNT,
                    avgAttestedMillis = avgAttested,
                    avgNonAttestedMillis = avgNonAttested,
                    diffMillis = diff,
                    source = measurement.source,
                    timerSource = measurementContext.timerSource,
                    affinity = measurementContext.affinity,
                    fallback = buildList {
                        add(measurement.detail)
                        addAll(fallback)
                        addAll(warnings)
                    },
                    failureReason = partialFailureReason,
                    stackCopyPayload = selectTimingSideChannelCopyPayload(
                        warmupFailures = warmupFailures.snapshot(),
                        gatewayFailures = session.diagnosticsCollector.snapshot(),
                    ),
                    detail = buildTimingSideChannelDetail(
                        source = measurement.source,
                        timerSource = measurementContext.timerSource,
                        affinity = measurementContext.affinity,
                        avgAttestedMillis = avgAttested,
                        avgNonAttestedMillis = avgNonAttested,
                        diffMillis = diff,
                        suspicious = suspicious,
                        sampleCount = filteredSeries.pairedSampleCount,
                        warmupCount = WARMUP_COUNT,
                        measurementDetail = measurement.detail,
                        timerFallbackReason = measurementContext.timerFallbackReason,
                        partialFailureReason = (listOfNotNull(partialFailureReason) + samplingNotes)
                            .joinToString("; "),
                    ),
                )
            } finally {
                cleanupDescriptors(
                    service = session.service,
                    descriptors = listOf(
                        effectiveAttestedDescriptor,
                        attestedDescriptor,
                        effectiveNonAttestedDescriptor,
                        nonAttestedDescriptor,
                        effectiveAttestKeyDescriptor,
                        attestKeyDescriptor,
                    ),
                )
                gatewayFailures = session.diagnosticsCollector.snapshot()
                binderClient.closeSession(session)
            }
        }.getOrElse { throwable ->
            TimingSideChannelResult(
                probeRan = true,
                measurementAvailable = false,
                sampleCount = 0,
                warmupCount = WARMUP_COUNT,
                source = "keystore2_security_level_proxy",
                timerSource = measurementContext.timerSource,
                affinity = measurementContext.affinity,
                fallback = fallback,
                failureReason = describeFailure(throwable),
                stackCopyPayload = selectTimingSideChannelCopyPayload(
                    warmupFailures = warmupFailures.snapshot(),
                    gatewayFailures = gatewayFailures,
                ),
                detail = describeFailure(throwable),
            )
        }
        registerTimerBridge.restoreCurrentThreadAffinity()
        return result
    }

    private fun warmUpPair(
        measurement: Measurement,
        attestedDescriptor: Any,
        nonAttestedDescriptor: Any,
        warnings: MutableList<String>,
        warmupFailures: CapturedThrowableCollector,
        describeFailure: (Throwable) -> String,
    ) {
        repeat(WARMUP_COUNT) { index ->
            runCatching { measurement.measureMillis(attestedDescriptor, measurement.timerSource) }
                .onFailure {
                    val phase = "warmup.attested[$index]"
                    val summary = describeFailure(it)
                    warmupFailures.record(phase = phase, summary = summary, throwable = it)
                    warnings += "$phase=$summary"
                }
            runCatching { measurement.measureMillis(nonAttestedDescriptor, measurement.timerSource) }
                .onFailure {
                    val phase = "warmup.nonAttested[$index]"
                    val summary = describeFailure(it)
                    warmupFailures.record(phase = phase, summary = summary, throwable = it)
                    warnings += "$phase=$summary"
                }
        }
    }

    private fun samplePairedSeries(
        measurement: Measurement,
        attestedDescriptor: Any,
        nonAttestedDescriptor: Any,
        warnings: MutableList<String>,
        describeFailure: (Throwable) -> String,
    ): PairedSampleSeries {
        val attestedSamples = mutableListOf<Double>()
        val nonAttestedSamples = mutableListOf<Double>()
        var firstFailure: String? = null
        var failedPairCount = 0
        repeat(LOOP_COUNT) { index ->
            val attested = runCatching { measurement.measureMillis(attestedDescriptor, measurement.timerSource) }
            val nonAttested = runCatching { measurement.measureMillis(nonAttestedDescriptor, measurement.timerSource) }

            if (attested.isSuccess && nonAttested.isSuccess) {
                attestedSamples += attested.getOrThrow()
                nonAttestedSamples += nonAttested.getOrThrow()
            } else {
                val failure = attested.exceptionOrNull()?.let(describeFailure)
                    ?: nonAttested.exceptionOrNull()?.let(describeFailure)
                    ?: "failed"
                if (firstFailure == null) {
                    firstFailure = failure
                }
                failedPairCount += 1
                warnings += "sample.paired[$index]=$failure"
            }
            throttleSamplingLoop(index)
        }
        return PairedSampleSeries(
            attemptedPairCount = LOOP_COUNT,
            attestedSamples = attestedSamples,
            nonAttestedSamples = nonAttestedSamples,
            failedPairCount = failedPairCount,
            failureReason = firstFailure,
        )
    }

    private fun throttleSamplingLoop(index: Int) {
        if ((index + 1) % SAMPLE_THROTTLE_EVERY_PAIRS != 0) {
            return
        }
        SystemClock.sleep(SAMPLE_THROTTLE_SLEEP_MS)
    }

    private fun measurePrivateGetKeyEntryMillis(
        service: Any,
        descriptor: Any,
        timerSource: StableTimeSource,
    ): Double {
        val start = timerSource.readNs()
        binderClient.getKeyEntry(service, descriptor)
        val end = timerSource.readNs()
        return (end - start) / 1_000_000.0
    }

    private fun cleanupDescriptors(
        service: Any,
        descriptors: List<Any>,
    ) {
        descriptors
            .distinctBy { System.identityHashCode(it) }
            .forEach { descriptor ->
                binderClient.deleteKey(service, descriptor)
            }
    }

    private fun bindMeasurementContext(initialMetadata: TimerMetadata): TimerMetadata {
        val preferred = registerTimerBridge.selectPreferredTimer(requestCpu0Affinity = true)
        val affinity = when {
            preferred.affinityStatus != "not_requested" -> preferred.affinityStatus
            registerTimerBridge.bindCurrentThreadToCpu0() -> "bound_cpu0"
            else -> initialMetadata.affinity
        }
        val preferRegisterTimer = preferred.registerTimerAvailable && preferred.timerSource.contains("cntvct", ignoreCase = true)
        val timerFallbackReason = preferred.fallbackReason ?: initialMetadata.timerFallbackReason
        val timerSourceLabel = if (preferRegisterTimer) preferred.timerSource else "clock_monotonic"
        return TimerMetadata(
            timerSource = timerSourceLabel,
            affinity = affinity,
            timerFallbackReason = timerFallbackReason,
            timeSource = StableTimeSource(
                preferRegisterTimer = preferRegisterTimer,
                registerTimerSource = { registerTimerBridge.readRegisterTimerNs() },
                monotonicSource = { System.nanoTime() },
            ),
        )
    }

    private fun resolveTimerMetadata(nativeSnapshot: NativeTeeSnapshot): TimerMetadata {
        val timerSource = nativeSnapshot.trickyStoreTimerSource.ifBlank { "clock_monotonic" }
        val affinity = nativeSnapshot.trickyStoreAffinityStatus.ifBlank { "not_requested" }
        return TimerMetadata(
            timerSource = timerSource,
            affinity = affinity,
            timerFallbackReason = nativeSnapshot.trickyStoreTimerFallbackReason,
            timeSource = StableTimeSource(
                preferRegisterTimer = false,
                registerTimerSource = { null },
                monotonicSource = { System.nanoTime() },
            ),
        )
    }

    private fun List<Double>.averageOrNull(): Double? = if (isEmpty()) null else average()

    private data class Measurement(
        val source: String,
        val detail: String,
        val measureMillis: (Any, StableTimeSource) -> Double,
        val timerSource: StableTimeSource,
    )

    private data class PairedSampleSeries(
        val attemptedPairCount: Int,
        val attestedSamples: List<Double>,
        val nonAttestedSamples: List<Double>,
        val failedPairCount: Int,
        val failureReason: String? = null,
    ) {
        val pairedSampleCount: Int
            get() = minOf(attestedSamples.size, nonAttestedSamples.size)

        fun filterOutlierPairs(): PairedSampleSeries {
            val pairedDiffs = pairedDiffSeries(attestedSamples, nonAttestedSamples)
            if (pairedDiffs.size < 8) {
                return this
            }
            val median = pairedDiffs.sorted()[pairedDiffs.size / 2]
            val absoluteDeviation = pairedDiffs.map { kotlin.math.abs(it - median) }.sorted()
            val mad = absoluteDeviation[absoluteDeviation.size / 2]
            if (mad == 0.0) {
                return this
            }
            val keepIndices = pairedDiffs.mapIndexedNotNull { index, diff ->
                if (kotlin.math.abs(diff - median) <= mad * 6.0) index else null
            }
            if (keepIndices.size == pairedDiffs.size || keepIndices.isEmpty()) {
                return this
            }
            return PairedSampleSeries(
                attemptedPairCount = attemptedPairCount,
                attestedSamples = keepIndices.map { attestedSamples[it] },
                nonAttestedSamples = keepIndices.map { nonAttestedSamples[it] },
                failedPairCount = failedPairCount,
                failureReason = failureReason,
            )
        }
    }

    private data class TimerMetadata(
        val timerSource: String,
        val affinity: String,
        val timerFallbackReason: String? = null,
        val timeSource: StableTimeSource,
    )

    companion object {
        private const val WARMUP_COUNT = 5
        private const val LOOP_COUNT = 500
        private const val SAMPLE_THROTTLE_EVERY_PAIRS = 20
        private const val SAMPLE_THROTTLE_SLEEP_MS = 25L
    }
}
