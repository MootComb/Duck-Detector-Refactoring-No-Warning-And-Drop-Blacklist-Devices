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

package com.eltavine.duckdetector.features.mount.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.mount.domain.MountFindingSeverity
import com.eltavine.duckdetector.features.mount.domain.MountReport
import com.eltavine.duckdetector.features.mount.domain.MountStage
import com.eltavine.duckdetector.features.mount.ui.model.MountImpactItemModel

internal fun buildImpactItems(report: MountReport): List<MountImpactItemModel> {
    return when (report.stage) {
        MountStage.LOADING -> listOf(
            MountImpactItemModel(
                text = "Gathering runtime mount and filesystem evidence.",
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
        )

        MountStage.FAILED -> buildList {
            if (report.zygoteNext.leakDetected) {
                add(
                    MountImpactItemModel(
                        text = "A root-managed mount remained visible from the Android 17 zygote_next native isolated process.",
                        status = DetectorStatus.danger(),
                    ),
                )
            }
            if (report.procMountViewTokenHit) {
                add(
                    MountImpactItemModel(
                        text = "A direct root token in a visible process mount table is strong evidence of a root-managed mount layer.",
                        status = DetectorStatus.danger(),
                    ),
                )
            } else if (report.procMountViewDivergent) {
                add(
                    MountImpactItemModel(
                        text = "Different processes expose different mount tables to the isolated observer, which can indicate selective mount hiding.",
                        status = DetectorStatus.warning(),
                    ),
                )
            }
            add(
                MountImpactItemModel(
                    text = report.errorMessage ?: "Mount scan failed.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )
        }

        MountStage.READY -> buildList {
            if (report.zygoteNext.leakDetected) {
                add(
                    MountImpactItemModel(
                        text = "A root-managed mount remained visible from the Android 17 zygote_next native isolated process.",
                        status = DetectorStatus.danger(),
                    ),
                )
            }
            if (report.procMountViewTokenHit) {
                add(
                    MountImpactItemModel(
                        text = "A direct root token in a visible process mount table is strong evidence of a root-managed mount layer.",
                        status = DetectorStatus.danger(),
                    ),
                )
            } else if (report.procMountViewDivergent) {
                add(
                    MountImpactItemModel(
                        text = "Different processes expose different mount tables to the isolated observer, which can indicate selective mount hiding.",
                        status = DetectorStatus.warning(),
                    ),
                )
            }
            report.impacts
                .filterNot { impact ->
                    (report.zygoteNext.leakDetected ||
                            report.procMountViewTokenHit ||
                            report.procMountViewDivergent) &&
                            impact.severity == MountFindingSeverity.SAFE
                }
                .mapTo(this) {
                    MountImpactItemModel(
                        text = it.text,
                        status = severityStatus(it.severity),
                    )
                }
        }
    }
}
