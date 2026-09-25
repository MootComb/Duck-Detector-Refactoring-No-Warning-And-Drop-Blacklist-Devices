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

package com.eltavine.duckdetector.features.su.domain

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind

fun SuReport.toDetectorStatus(): DetectorStatus {
    return when (stage) {
        SuStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
        SuStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
        SuStage.READY -> when {
            hasRootIndicators -> DetectorStatus.danger()
            !nativeAvailable || unobservablePathCount > 0 -> DetectorStatus.info(InfoKind.SUPPORT)
            else -> DetectorStatus.allClear()
        }
    }
}
