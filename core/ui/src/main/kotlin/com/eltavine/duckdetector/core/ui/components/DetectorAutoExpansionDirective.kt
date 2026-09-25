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

package com.eltavine.duckdetector.core.ui.components

import androidx.compose.runtime.ProvidableCompositionLocal
import androidx.compose.runtime.compositionLocalOf
import com.eltavine.duckdetector.core.evidence.DetectorId

public data class DetectorAutoExpansionDirective(
    val detectorIds: Set<DetectorId> = emptySet(),
    val onConsumed: (DetectorId) -> Unit = {},
) {
    public fun shouldExpand(detectorId: DetectorId?): Boolean {
        return detectorId != null && detectorId in detectorIds
    }
}

/** Identity of the detector whose card is being composed; the dashboard provides it around each card. */
public val LocalDetectorIdentity: ProvidableCompositionLocal<DetectorId?> =
    compositionLocalOf { null }

public val LocalDetectorAutoExpansionDirective: ProvidableCompositionLocal<DetectorAutoExpansionDirective> =
    compositionLocalOf { DetectorAutoExpansionDirective() }
