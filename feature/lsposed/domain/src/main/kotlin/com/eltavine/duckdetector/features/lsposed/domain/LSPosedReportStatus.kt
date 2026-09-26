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

package com.eltavine.duckdetector.features.lsposed.domain

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind

fun LSPosedReport.toDetectorStatus(): DetectorStatus {
    return when (stage) {
        LSPosedStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
        LSPosedStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
        LSPosedStage.READY -> when {
            hasDangerSignals -> DetectorStatus.danger()
            hasWarningSignals -> DetectorStatus.warning()
            hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
            else -> DetectorStatus.allClear()
        }
    }
}

fun LSPosedReport.hasReducedCoverage(): Boolean {
    return !nativeAvailable ||
            !nativeMapsAvailable ||
            !nativeHeapAvailable ||
            !zygotePermissionAvailable ||
            !runtimeArtifactAvailable ||
            !logcatAvailable ||
            !dirtyPolicyAvailable ||
            packageVisibility != LSPosedPackageVisibility.FULL
}
