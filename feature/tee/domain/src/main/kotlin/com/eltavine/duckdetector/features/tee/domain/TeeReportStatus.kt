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

package com.eltavine.duckdetector.features.tee.domain

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind

fun TeeReport.toDetectorStatus(): DetectorStatus = when (verdict) {
    TeeVerdict.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
    TeeVerdict.CONSISTENT,
    TeeVerdict.SUSPICIOUS -> when {
        // Dashboard aggregates only TeeCardModel.status; consume reducer structure, not prose or row titles.
        // Dashboard 只聚合 TeeCardModel.status；这里消费 reducer 的结构化级别，不解析文案或行标题。
        supplementaryReviewLevel == TeeSignalLevel.FAIL -> DetectorStatus.danger()
        supplementaryReviewLevel == TeeSignalLevel.WARN -> DetectorStatus.warning()
        verdict == TeeVerdict.SUSPICIOUS -> DetectorStatus.warning()
        supplementaryIndicatorCount > 0 -> DetectorStatus.warning()
        !nativeProbesAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
        else -> DetectorStatus.allClear()
    }
    TeeVerdict.TAMPERED, TeeVerdict.BROKEN -> DetectorStatus.danger()
    TeeVerdict.INCONCLUSIVE -> DetectorStatus.info(InfoKind.ERROR)
}
