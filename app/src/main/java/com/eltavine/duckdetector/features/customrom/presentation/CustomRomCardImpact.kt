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

package com.eltavine.duckdetector.features.customrom.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.customrom.domain.CustomRomPackageVisibility
import com.eltavine.duckdetector.features.customrom.domain.CustomRomReport
import com.eltavine.duckdetector.features.customrom.domain.CustomRomStage
import com.eltavine.duckdetector.features.customrom.ui.model.CustomRomImpactItemModel

internal fun buildImpactItems(report: CustomRomReport): List<CustomRomImpactItemModel> {
    return when (report.stage) {
        CustomRomStage.LOADING -> listOf(
            CustomRomImpactItemModel(
                text = "Gathering local firmware branding and framework evidence.",
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
        )

        CustomRomStage.FAILED -> listOf(
            CustomRomImpactItemModel(
                text = report.errorMessage ?: "Custom ROM scan failed.",
                status = DetectorStatus.info(InfoKind.ERROR),
            ),
        )

        CustomRomStage.READY -> when {
            report.hasIndicators -> buildList {
                add(
                    CustomRomImpactItemModel(
                        text = "Aftermarket firmware can legitimately alter build properties, property storage, bootloader state, privileged services, and security defaults.",
                        status = DetectorStatus.warning(),
                    ),
                )
                add(
                    CustomRomImpactItemModel(
                        text = "Attestation behavior, Play Integrity, and some banking or DRM apps may differ on custom ROMs or modified boot chains.",
                        status = DetectorStatus.warning(),
                    ),
                )
                add(
                    CustomRomImpactItemModel(
                        text = "This signal alone does not prove malicious compromise or active root access.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )
            }

            else -> buildList {
                if (!report.nativeAvailable) {
                    add(
                        CustomRomImpactItemModel(
                            text = "Native coverage was unavailable on this build, so clean native trace results are not available.",
                            status = DetectorStatus.info(InfoKind.SUPPORT),
                        ),
                    )
                } else if (report.hasReducedCoverage()) {
                    add(
                        CustomRomImpactItemModel(
                            text = "No custom ROM signature surfaced from available probes, but package visibility, property-area, or native symbol coverage was incomplete.",
                            status = DetectorStatus.info(InfoKind.SUPPORT),
                        ),
                    )
                } else {
                    add(
                        CustomRomImpactItemModel(
                            text = "No common aftermarket firmware branding, property-area, or framework traces were found.",
                            status = DetectorStatus.allClear(),
                        ),
                    )
                }
                if (report.packageVisibility != CustomRomPackageVisibility.FULL) {
                    add(
                        CustomRomImpactItemModel(
                            text = if (report.packageVisibility == CustomRomPackageVisibility.RESTRICTED) {
                                "Package visibility was scoped, so clean app-level evidence may be incomplete."
                            } else {
                                "Package inventory was unavailable or anomalous, so app-level absence is inconclusive."
                            },
                            status = DetectorStatus.info(InfoKind.SUPPORT),
                        ),
                    )
                }
                add(
                    CustomRomImpactItemModel(
                        text = "A determined ROM can remove obvious signatures, so absence is not proof of stock firmware.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )
            }
        }
    }
}

internal fun CustomRomReport.toDetectorStatus(): DetectorStatus {
    return when (stage) {
        CustomRomStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
        CustomRomStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
        CustomRomStage.READY -> when {
            hasIndicators -> DetectorStatus.warning()
            hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
            else -> DetectorStatus.allClear()
        }
    }
}
