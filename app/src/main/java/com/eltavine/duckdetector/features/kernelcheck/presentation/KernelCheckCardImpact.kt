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
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckReport
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckStage
import com.eltavine.duckdetector.features.kernelcheck.ui.model.KernelCheckImpactItemModel

internal fun buildImpactItems(report: KernelCheckReport): List<KernelCheckImpactItemModel> {
    return when (report.stage) {
        KernelCheckStage.LOADING -> listOf(
            KernelCheckImpactItemModel(
                text = "Gathering local kernel evidence.",
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
        )

        KernelCheckStage.FAILED -> listOf(
            KernelCheckImpactItemModel(
                text = report.errorMessage ?: "Kernel Check scan failed.",
                status = DetectorStatus.info(InfoKind.ERROR),
            ),
        )

        KernelCheckStage.READY -> when {
            report.hasHardIndicators -> listOfNotNull(
                KernelCheckImpactItemModel(
                    text = "The kernel identity differs between the sources that export it, so the version this device reports to apps is being rewritten rather than simply being unusual.",
                    status = DetectorStatus.danger(),
                ).takeIf { report.hasIdentityMismatch },
                KernelCheckImpactItemModel(
                    text = "A same-CPU cached/MIDR_EL1 mismatch indicates that the kernel's cached processor identity was changed independently of its ARM64 register-emulation path.",
                    status = DetectorStatus.danger(),
                ).takeIf { report.hasCpuIdentityMismatch },
                KernelCheckImpactItemModel(
                    text = "Modified or community-built kernels can change trust posture, boot state, and device integrity behavior.",
                    status = DetectorStatus.danger(),
                ),
                KernelCheckImpactItemModel(
                    text = "These heuristics do not prove malicious compromise, but they do indicate the kernel differs from conservative stock expectations.",
                    status = DetectorStatus.warning(),
                ),
                KernelCheckImpactItemModel(
                    text = "Play Integrity, banking apps, or DRM-sensitive apps may react differently on such kernels.",
                    status = DetectorStatus.warning(),
                ),
            )

            report.hasReviewInfoIndicators -> listOf(
                KernelCheckImpactItemModel(
                    text = "Behavior-level signals are weaker than direct naming or boot parameter hits and should be interpreted with device context.",
                    status = DetectorStatus.warning(),
                ),
                KernelCheckImpactItemModel(
                    text = "A partial CVE patch or exposed kernel pointers can reflect aftermarket hardening gaps rather than active compromise.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            report.hasInformationalCveState -> listOf(
                KernelCheckImpactItemModel(
                    text = "The CVE-2024-43093 probe suggests the path-filter fix is missing or incomplete, but this remains informational context rather than a root or tamper verdict.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                KernelCheckImpactItemModel(
                    text = "This signal is useful for hardening posture, but it should not elevate the entire kernel card to warning on its own.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            report.cvePatchState == KernelCheckCvePatchState.INCONCLUSIVE -> listOf(
                KernelCheckImpactItemModel(
                    text = "The CVE-2024-43093 probe was inconclusive, so this card cannot claim the path-filter fix is present.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                KernelCheckImpactItemModel(
                    text = "An inconclusive result is weaker than a warning and can happen when direct Android/data listing behavior does not allow a clean bypass experiment.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            !report.nativeAvailable -> listOf(
                KernelCheckImpactItemModel(
                    text = "No hard kernel naming marker surfaced from fallback identity reads, but native-only /proc checks were unavailable.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
                KernelCheckImpactItemModel(
                    text = "This support-only result has reduced coverage and should not be read as a strong clean kernel verdict.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            else -> listOf(
                KernelCheckImpactItemModel(
                    text = "No suspicious naming, boot parameter, or behavior signal surfaced.",
                    status = DetectorStatus.allClear(),
                ),
                KernelCheckImpactItemModel(
                    text = "This remains heuristic evidence rather than proof of a fully stock device.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )
        }
    }
}
