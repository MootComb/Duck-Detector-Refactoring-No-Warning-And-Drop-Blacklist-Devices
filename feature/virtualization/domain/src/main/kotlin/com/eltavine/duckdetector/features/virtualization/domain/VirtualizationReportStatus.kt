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

package com.eltavine.duckdetector.features.virtualization.domain

import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind

fun VirtualizationReport.toDetectorStatus(): DetectorStatus {
    return when (stage) {
        VirtualizationStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
        VirtualizationStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
        VirtualizationStage.READY -> when {
            dangerSignals.isNotEmpty() -> DetectorStatus.danger()
            warningSignals.isNotEmpty() -> DetectorStatus.warning()
            onlyHostAppCorroboration -> DetectorStatus.info(InfoKind.SUPPORT)
            hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
            else -> DetectorStatus.allClear()
        }
    }
}

fun VirtualizationReport.hasReducedCoverage(): Boolean {
    return !nativeAvailable ||
            !startupPreloadAvailable ||
            !startupPreloadContextValid ||
            !crossProcessAvailable ||
            !isolatedProcessAvailable ||
            !eglAvailable ||
            !mountNamespaceAvailable ||
            !syscallPackSupported ||
            packageVisibility != InstalledPackageVisibility.FULL
}
