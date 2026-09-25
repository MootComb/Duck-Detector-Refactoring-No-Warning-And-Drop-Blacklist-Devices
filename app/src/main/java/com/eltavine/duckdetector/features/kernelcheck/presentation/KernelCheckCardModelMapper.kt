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
import com.eltavine.duckdetector.features.kernelcheck.ui.model.KernelCheckCardModel
import com.eltavine.duckdetector.features.kernelcheck.ui.model.KernelCheckHeaderFactModel

class KernelCheckCardModelMapper {
    fun map(
        report: KernelCheckReport,
    ): KernelCheckCardModel {
        return KernelCheckCardModel(
            title = "Kernel Check",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            identityRows = buildIdentityRows(report),
            anomalyRows = buildAnomalyRows(report),
            behaviorRows = buildBehaviorRows(report),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
        )
    }

    private fun buildSubtitle(report: KernelCheckReport): String {
        return when (report.stage) {
            KernelCheckStage.LOADING -> "uname + /proc/version + boot cmdline + CVE heuristic"
            KernelCheckStage.FAILED -> "local kernel probe failed"
            KernelCheckStage.READY -> {
                val nativeLabel =
                    if (report.nativeAvailable) "native /proc" else "fallback file reads"
                "${report.checkedKeywordCount} keyword families · ${report.checkedCmdlineRuleCount} cmdline rules · $nativeLabel"
            }
        }
    }

    private fun buildVerdict(report: KernelCheckReport): String {
        return when (report.stage) {
            KernelCheckStage.LOADING -> "Scanning kernel identity"
            KernelCheckStage.FAILED -> "Kernel Check scan failed"
            KernelCheckStage.READY -> when {
                report.hasHardIndicators -> "${report.hardFindingCount} suspicious kernel signal(s)"
                report.hasReviewInfoIndicators -> "Kernel behavior needs review"
                report.hasInformationalCveState -> "CVE patch state is informational"
                report.cvePatchState == KernelCheckCvePatchState.INCONCLUSIVE -> "CVE patch state inconclusive"
                !report.nativeAvailable -> "Kernel scan has reduced native coverage"
                else -> "No suspicious kernel markers"
            }
        }
    }

    private fun buildSummary(report: KernelCheckReport): String {
        return when (report.stage) {
            KernelCheckStage.LOADING ->
                "Kernel naming, boot parameter, pointer-exposure, and Unicode path-bypass heuristics are collecting local evidence."

            KernelCheckStage.FAILED ->
                report.errorMessage ?: "Kernel Check failed before evidence could be assembled."

            KernelCheckStage.READY -> when {
                report.hasCpuIdentityMismatch ->
                    "A logical CPU's cached ARM64 identity disagrees with MIDR_EL1 observed while pinned to that same CPU, which is a high-confidence sign of runtime CPU identity rewriting."

                report.hasIdentityMismatch ->
                    "The kernel identity read through uname disagrees with the identity exported through /proc or with the value captured when this app's runtime started, which points at active kernel version spoofing."

                report.hasHardIndicators ->
                    "Kernel identity text or boot-time native checks surfaced markers commonly seen on modified or community-built kernels."

                report.hasReviewInfoIndicators ->
                    "Kernel behavior heuristics surfaced review-worthy signals, but they are weaker than direct naming or boot parameter anomalies."

                report.hasInformationalCveState ->
                    "The Unicode path-bypass probe suggests CVE-2024-43093 is not fully patched, but this is informational context rather than a kernel-compromise signal."

                report.cvePatchState == KernelCheckCvePatchState.INCONCLUSIVE ->
                    "The Unicode path-bypass probe could not determine whether CVE-2024-43093 is fully patched on this device."

                !report.nativeAvailable ->
                    "No hard kernel naming marker surfaced from fallback identity reads, but native-only /proc checks were unavailable on this build."

                else ->
                    "Kernel identity, boot parameters, and behavior heuristics stayed within expected bounds."
            }
        }
    }

    private fun buildHeaderFacts(report: KernelCheckReport): List<KernelCheckHeaderFactModel> {
        return when (report.stage) {
            KernelCheckStage.LOADING -> placeholderFacts(
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            KernelCheckStage.FAILED -> placeholderFacts(
                "Error",
                DetectorStatus.info(InfoKind.ERROR)
            )

            KernelCheckStage.READY -> listOf(
                KernelCheckHeaderFactModel(
                    label = "Identity",
                    value = when {
                        report.identityFindingCount > 0 -> report.identityFindingCount.toString()
                        report.unameOutput.isBlank() && report.procVersion.isBlank() -> "N/A"
                        else -> "Clean"
                    },
                    status = when {
                        report.identityFindingCount > 0 -> DetectorStatus.danger()
                        report.unameOutput.isBlank() && report.procVersion.isBlank() -> DetectorStatus.info(
                            InfoKind.SUPPORT
                        )

                        else -> DetectorStatus.allClear()
                    },
                ),
                KernelCheckHeaderFactModel(
                    label = "Boot",
                    value = when {
                        report.bootFindingCount > 0 -> report.bootFindingCount.toString()
                        report.nativeAvailable || report.procCmdline.isNotBlank() -> "Clean"
                        else -> "N/A"
                    },
                    status = when {
                        report.bootFindingCount > 0 -> DetectorStatus.danger()
                        report.nativeAvailable || report.procCmdline.isNotBlank() -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                KernelCheckHeaderFactModel(
                    label = "Behavior",
                    value = when {
                        report.hasReviewInfoIndicators -> report.reviewInfoFindingCount.toString()
                        report.hasInformationalCveState -> report.cvePatchState.label
                        report.cvePatchState == KernelCheckCvePatchState.INCONCLUSIVE -> "Inconclusive"
                        report.nativeAvailable -> "OK"
                        else -> "Partial"
                    },
                    status = when {
                        report.hasReviewInfoIndicators -> DetectorStatus.warning()
                        report.hasInformationalCveState -> DetectorStatus.info(InfoKind.SUPPORT)
                        report.cvePatchState == KernelCheckCvePatchState.INCONCLUSIVE -> DetectorStatus.info(
                            InfoKind.SUPPORT
                        )

                        report.nativeAvailable -> DetectorStatus.allClear()
                        else -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                KernelCheckHeaderFactModel(
                    label = "Native",
                    value = if (report.nativeAvailable) "Loaded" else "N/A",
                    status = if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                        InfoKind.SUPPORT
                    ),
                ),
            )
        }
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus,
    ): List<KernelCheckHeaderFactModel> {
        return listOf(
            KernelCheckHeaderFactModel("Identity", value, status),
            KernelCheckHeaderFactModel("Boot", value, status),
            KernelCheckHeaderFactModel("Behavior", value, status),
            KernelCheckHeaderFactModel("Native", value, status),
        )
    }
}
