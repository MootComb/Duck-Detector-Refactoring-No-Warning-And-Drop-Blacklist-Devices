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

package com.eltavine.duckdetector.features.lsposed.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedReport
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedStage
import com.eltavine.duckdetector.features.lsposed.domain.hasReducedCoverage
import com.eltavine.duckdetector.features.lsposed.presentation.model.LSPosedImpactItemModel

internal fun buildImpactItems(report: LSPosedReport): List<LSPosedImpactItemModel> {
    return when (report.stage) {
        LSPosedStage.LOADING -> listOf(
            LSPosedImpactItemModel(
                text = "Gathering class, ClassLoader, Binder, runtime-artifact, logcat, package, SELinux policy, and native runtime evidence.",
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
        )

        LSPosedStage.FAILED -> listOf(
            LSPosedImpactItemModel(
                text = report.errorMessage ?: "LSPosed scan failed.",
                status = DetectorStatus.info(InfoKind.ERROR),
            ),
        )

        LSPosedStage.READY -> when {
            report.hasDangerSignals -> listOf(
                LSPosedImpactItemModel(
                    text = "Loaded Xposed classes, bridge fields, Binder bridge responses, runtime artifacts, logcat leaks, dirty SELinux policy rules, and native LSPosed keywords are stronger evidence than package residue because they touch the current process, live policy, or system services directly.",
                    status = DetectorStatus.danger(),
                ),
                LSPosedImpactItemModel(
                    text = "This card still observes only a narrow runtime slice. Read it together with Memory, Native Root, Mount, and System Properties when the setup is actively hiding itself.",
                    status = DetectorStatus.warning(),
                ),
            )

            report.hasWarningSignals -> listOf(
                LSPosedImpactItemModel(
                    text = "Manager packages, Xposed module meta-data, or dirty SELinux policy drift show framework or root-policy residue, but they do not prove the current process is hooked right now.",
                    status = DetectorStatus.warning(),
                ),
                LSPosedImpactItemModel(
                    text = "Hardened setups can avoid exposing direct stack or class evidence in the current app, so yellow-only results still deserve correlation with other detector cards.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            else -> if (report.hasReducedCoverage()) {
                listOf(
                    LSPosedImpactItemModel(
                        text = "No LSPosed/Xposed signal surfaced from available probes, but one or more runtime evidence paths were unavailable.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                    LSPosedImpactItemModel(
                        text = "This support-only result lowers confidence only for the probes that actually ran.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )
            } else {
                listOf(
                    LSPosedImpactItemModel(
                        text = "The current app process did not expose LSPosed/Xposed class loading, Binder bridge behavior, or LSPosed-native runtime strings.",
                        status = DetectorStatus.allClear(),
                    ),
                    LSPosedImpactItemModel(
                        text = "A clean result lowers confidence in active LSPosed-style hooking for this process, but it does not prove the whole device is stock.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )
            }
        }
    }
}
