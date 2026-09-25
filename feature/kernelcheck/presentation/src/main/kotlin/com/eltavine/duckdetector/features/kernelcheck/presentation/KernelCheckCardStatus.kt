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

package com.eltavine.duckdetector.features.kernelcheck.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckCvePatchState
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckMethod
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckMethodOutcome
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckMethodResult
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckReport
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckStage

internal fun cvePatchStatus(
    state: KernelCheckCvePatchState,
): DetectorStatus {
    return when (state) {
        KernelCheckCvePatchState.UNPATCHED,
        KernelCheckCvePatchState.PARTIALLY_PATCHED -> DetectorStatus.info(InfoKind.SUPPORT)

        KernelCheckCvePatchState.PATCHED -> DetectorStatus.allClear()
        KernelCheckCvePatchState.INCONCLUSIVE -> DetectorStatus.info(InfoKind.SUPPORT)
    }
}

internal fun methodStatus(result: KernelCheckMethodResult): DetectorStatus {
    return when (result.outcome) {
        KernelCheckMethodOutcome.CLEAN -> DetectorStatus.allClear()
        KernelCheckMethodOutcome.DETECTED -> DetectorStatus.danger()
        KernelCheckMethodOutcome.INFO -> {
            if (result.method == KernelCheckMethod.CVE_PATCH_CHECK) {
                DetectorStatus.info(InfoKind.SUPPORT)
            } else {
                DetectorStatus.warning()
            }
        }

        KernelCheckMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
    }
}

internal fun KernelCheckReport.toDetectorStatus(): DetectorStatus {
    return when (stage) {
        KernelCheckStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
        KernelCheckStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
        KernelCheckStage.READY -> when {
            hasHardIndicators -> DetectorStatus.danger()
            hasReviewInfoIndicators -> DetectorStatus.warning()
            hasInformationalCveState -> DetectorStatus.info(InfoKind.SUPPORT)
            cvePatchState == KernelCheckCvePatchState.INCONCLUSIVE -> DetectorStatus.info(
                InfoKind.SUPPORT
            )

            !nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
            else -> DetectorStatus.allClear()
        }
    }
}
