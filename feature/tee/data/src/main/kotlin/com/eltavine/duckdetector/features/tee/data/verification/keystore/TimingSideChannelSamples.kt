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

internal data class Measurement(
    val source: String,
    val detail: String,
    val measureMillis: (Any, StableTimeSource) -> Double,
    val timerSource: StableTimeSource,
)

internal data class PairedSampleSeries(
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

internal data class TimerMetadata(
    val timerSource: String,
    val affinity: String,
    val timerFallbackReason: String? = null,
    val timeSource: StableTimeSource,
)
