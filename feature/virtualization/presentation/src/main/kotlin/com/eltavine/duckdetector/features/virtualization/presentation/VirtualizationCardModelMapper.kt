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

package com.eltavine.duckdetector.features.virtualization.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationImpact
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationMethodOutcome
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationMethodResult
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationReport
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignal
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationStage
import com.eltavine.duckdetector.features.virtualization.domain.hasReducedCoverage
import com.eltavine.duckdetector.features.virtualization.domain.toDetectorStatus
import com.eltavine.duckdetector.features.virtualization.presentation.model.VirtualizationCardModel
import com.eltavine.duckdetector.features.virtualization.presentation.model.VirtualizationDetailRowModel
import com.eltavine.duckdetector.features.virtualization.presentation.model.VirtualizationHeaderFactModel
import com.eltavine.duckdetector.features.virtualization.presentation.model.VirtualizationImpactItemModel

class VirtualizationCardModelMapper {

    fun map(report: VirtualizationReport): VirtualizationCardModel {
        return VirtualizationCardModel(
            title = "Virtualization",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            environmentRows = buildRows(
                report.stage,
                report.environmentRows,
                listOf("ro.kernel.qemu", "Build cluster", "QEMU guest properties"),
            ),
            runtimeRows = buildRows(
                report.stage,
                report.runtimeRows,
                listOf("qemud service", "AVF runtime", "Emulator device node", "Host dex path"),
            ),
            consistencyRows = buildRows(
                report.stage,
                report.consistencyRows,
                listOf(
                    "Classpath/source mismatch",
                    "Current package missing from UID",
                    "Cross-process path drift"
                ),
            ),
            honeypotRows = buildRows(
                report.stage,
                report.honeypotRows,
                listOf("Native timing trap", "ASM counter trap", "Sacrificial openat2"),
            ),
            hostAppRows = buildRows(
                report.stage,
                report.hostAppRows,
                listOf("VMOS", "Parallel Space", "VirtualXposed"),
            ),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
            references = REFERENCES,
        )
    }

    private fun buildSubtitle(report: VirtualizationReport): String {
        return when (report.stage) {
            VirtualizationStage.LOADING -> "properties + build + runtime artifacts + helper process + honeypots"
            VirtualizationStage.FAILED -> "local virtualization scan failed"
            VirtualizationStage.READY -> buildString {
                append("${report.environmentHitCount} env · ${report.translationHitCount} translation · ${report.runtimeArtifactHitCount} runtime")
                if (report.dexPathHitCount > 0) {
                    append(" · ${report.dexPathHitCount} dex")
                }
                if (report.uidIdentityHitCount > 0) {
                    append(" · ${report.uidIdentityHitCount} uid")
                }
                if (report.honeypotHitCount > 0) {
                    append(" · ${report.honeypotHitCount} trap hit(s)")
                }
                if (report.hostAppCorroborationCount > 0) {
                    append(" · ${report.hostAppCorroborationCount} host app(s)")
                }
            }
        }
    }

    private fun buildVerdict(report: VirtualizationReport): String {
        return when (report.stage) {
            VirtualizationStage.LOADING -> "Scanning virtualization and translation state"
            VirtualizationStage.FAILED -> "Virtualization scan failed"
            VirtualizationStage.READY -> when {
                report.dangerSignals.isNotEmpty() -> "${report.dangerSignals.size} direct virtualization signal(s)"
                report.warningSignals.isNotEmpty() -> "${report.warningSignals.size} virtualization signal(s) need review"
                report.onlyHostAppCorroboration -> "${report.hostAppCorroborationCount} corroborating host app(s)"
                report.hasReducedCoverage() -> "Virtualization scan has reduced coverage"
                else -> "No direct virtualization signal"
            }
        }
    }

    private fun buildSummary(report: VirtualizationReport): String {
        return when (report.stage) {
            VirtualizationStage.LOADING ->
                "Properties, Build fields, runtime artifacts, startup preload, helper-process consistency, and native or ASM honeypots are collecting local evidence."

            VirtualizationStage.FAILED ->
                report.errorMessage
                    ?: "Virtualization scan failed before evidence could be assembled."

            VirtualizationStage.READY -> when {
                report.dangerSignals.isNotEmpty() ->
                    "The current app context contains direct emulator, AVF guest, device-node, classpath, UID, or runtime-service evidence."

                report.warningSignals.isNotEmpty() ->
                    "The app is not conclusively inside a guest, but translation, renderer, classpath drift, consistency drift, or honeypot anomalies still require review."

                report.onlyHostAppCorroboration ->
                    "Known virtualization host apps are present on the device, but current process probes did not confirm guest execution."

                report.hasReducedCoverage() ->
                    "No direct virtualization signal surfaced from the available probes, but one or more native, preload, helper-process, graphics, namespace, or syscall paths were unavailable."

                else ->
                    "No direct emulator, AVF guest, native-bridge, or cross-process drift artifact surfaced from the current app context."
            }
        }
    }

    private fun buildHeaderFacts(report: VirtualizationReport): List<VirtualizationHeaderFactModel> {
        return when (report.stage) {
            VirtualizationStage.LOADING -> placeholderFacts(
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            VirtualizationStage.FAILED -> placeholderFacts(
                "Error",
                DetectorStatus.info(InfoKind.ERROR)
            )

            VirtualizationStage.READY -> listOf(
                VirtualizationHeaderFactModel(
                    label = "Danger",
                    value = report.dangerSignals.size.toString(),
                    status = when {
                        report.dangerSignals.isNotEmpty() -> DetectorStatus.danger()
                        report.hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.allClear()
                    },
                ),
                VirtualizationHeaderFactModel(
                    label = "Review",
                    value = report.warningSignals.size.toString(),
                    status = when {
                        report.warningSignals.isNotEmpty() -> DetectorStatus.warning()
                        report.hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                        else -> DetectorStatus.allClear()
                    },
                ),
                VirtualizationHeaderFactModel(
                    label = "Host",
                    value = report.hostAppCorroborationCount.toString(),
                    status = if (report.hostAppCorroborationCount == 0) {
                        DetectorStatus.allClear()
                    } else {
                        DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                VirtualizationHeaderFactModel(
                    label = "Native",
                    value = if (report.nativeAvailable) "Loaded" else "N/A",
                    status = if (report.nativeAvailable) {
                        DetectorStatus.allClear()
                    } else {
                        DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
            )
        }
    }

    private fun buildRows(
        stage: VirtualizationStage,
        rows: List<VirtualizationSignal>,
        placeholders: List<String>,
    ): List<VirtualizationDetailRowModel> {
        return when (stage) {
            VirtualizationStage.LOADING -> placeholderRows(
                placeholders,
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT),
            )

            VirtualizationStage.FAILED -> placeholderRows(
                placeholders,
                "Error",
                DetectorStatus.info(InfoKind.ERROR),
            )

            VirtualizationStage.READY -> if (rows.isEmpty()) {
                listOf(
                    VirtualizationDetailRowModel(
                        label = "Status",
                        value = "Clean",
                        status = DetectorStatus.allClear(),
                        detail = "No findings were produced for this section.",
                    ),
                )
            } else {
                rows.map(::signalRow)
            }
        }
    }

    private fun buildImpactItems(report: VirtualizationReport): List<VirtualizationImpactItemModel> {
        return when (report.stage) {
            VirtualizationStage.LOADING -> listOf(
                VirtualizationImpactItemModel(
                    text = "Gathering current-process guest and translation evidence.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            VirtualizationStage.FAILED -> listOf(
                VirtualizationImpactItemModel(
                    text = report.errorMessage ?: "Virtualization scan failed.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )

            VirtualizationStage.READY -> {
                if (
                    report.dangerSignals.isEmpty() &&
                    report.warningSignals.isEmpty() &&
                    !report.onlyHostAppCorroboration &&
                    report.hasReducedCoverage()
                ) {
                    listOf(
                        VirtualizationImpactItemModel(
                            text = "No direct virtualization signal surfaced from available probes, but coverage was incomplete.",
                            status = DetectorStatus.info(InfoKind.SUPPORT),
                        ),
                        VirtualizationImpactItemModel(
                            text = "Unavailable helper or native paths reduce confidence without implying a positive detection.",
                            status = DetectorStatus.info(InfoKind.SUPPORT),
                        ),
                    )
                } else {
                    report.impacts.map { impact ->
                        VirtualizationImpactItemModel(
                            text = impact.text,
                            status = impact.toStatus(),
                        )
                    }
                }
            }
        }
    }

    private fun buildMethodRows(report: VirtualizationReport): List<VirtualizationDetailRowModel> {
        return when (report.stage) {
            VirtualizationStage.LOADING -> placeholderRows(
                METHOD_LABELS,
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT),
            )

            VirtualizationStage.FAILED -> placeholderRows(
                METHOD_LABELS,
                "Failed",
                DetectorStatus.info(InfoKind.ERROR),
            )

            VirtualizationStage.READY -> report.methods.map { result ->
                VirtualizationDetailRowModel(
                    label = result.label,
                    value = result.summary,
                    status = result.toStatus(),
                    detail = result.detail,
                    detailMonospace = true,
                )
            }
        }
    }

    private fun signalRow(signal: VirtualizationSignal): VirtualizationDetailRowModel {
        return VirtualizationDetailRowModel(
            label = signal.label,
            value = signal.value,
            status = signal.toStatus(),
            detail = signal.detail,
            detailMonospace = signal.detailMonospace,
        )
    }

    private fun VirtualizationSignal.toStatus(): DetectorStatus {
        return when (severity) {
            VirtualizationSignalSeverity.DANGER -> DetectorStatus.danger()
            VirtualizationSignalSeverity.WARNING -> DetectorStatus.warning()
            VirtualizationSignalSeverity.INFO -> DetectorStatus.info(InfoKind.SUPPORT)
            VirtualizationSignalSeverity.SAFE -> DetectorStatus.allClear()
        }
    }

    private fun VirtualizationMethodResult.toStatus(): DetectorStatus {
        return when (outcome) {
            VirtualizationMethodOutcome.DANGER -> DetectorStatus.danger()
            VirtualizationMethodOutcome.WARNING -> DetectorStatus.warning()
            VirtualizationMethodOutcome.INFO -> DetectorStatus.info(InfoKind.SUPPORT)
            VirtualizationMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
            VirtualizationMethodOutcome.CLEAN -> DetectorStatus.allClear()
        }
    }

    private fun VirtualizationImpact.toStatus(): DetectorStatus {
        return when (severity) {
            VirtualizationSignalSeverity.DANGER -> DetectorStatus.danger()
            VirtualizationSignalSeverity.WARNING -> DetectorStatus.warning()
            VirtualizationSignalSeverity.INFO -> DetectorStatus.info(InfoKind.SUPPORT)
            VirtualizationSignalSeverity.SAFE -> DetectorStatus.allClear()
        }
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus,
    ): List<VirtualizationHeaderFactModel> {
        return listOf(
            VirtualizationHeaderFactModel("Danger", value, status),
            VirtualizationHeaderFactModel("Review", value, status),
            VirtualizationHeaderFactModel("Host", value, status),
            VirtualizationHeaderFactModel("Native", value, status),
        )
    }

    companion object {
        private val METHOD_LABELS = listOf(
            "Properties and build",
            "Dex and classpath",
            "UID identity",
            "Runtime artifacts",
            "Graphics renderer",
            "Native bridge",
            "Startup preload",
            "Cross-process consistency",
            "Isolated-process consistency",
            "Host apps",
            "Native honeypots",
            "ASM honeypots",
            "Sacrificial syscall pack",
        )
        private val REFERENCES = listOf(
            "Android Virtualization Framework: https://source.android.com/docs/core/virtualization",
            "Android Emulator: https://developer.android.com/studio/run/emulator",
            "AOSP property_contexts: https://android.googlesource.com/platform/system/sepolicy/+/refs/heads/main/private/property_contexts",
        )
    }
}
