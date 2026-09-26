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
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckFinding
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckFindingKind
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckMethod
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckReport
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckStage
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelIdentityField
import com.eltavine.duckdetector.features.kernelcheck.presentation.model.KernelCheckDetailRowModel

internal fun buildIdentityRows(report: KernelCheckReport): List<KernelCheckDetailRowModel> {
    return when (report.stage) {
        KernelCheckStage.LOADING -> placeholderRows(
            labels = listOf("uname -a", "/proc/version", "/proc/cmdline"),
            status = DetectorStatus.info(InfoKind.SUPPORT),
            value = "Pending",
            monospace = true,
        )

        KernelCheckStage.FAILED -> placeholderRows(
            labels = listOf("uname -a", "/proc/version", "/proc/cmdline"),
            status = DetectorStatus.info(InfoKind.ERROR),
            value = "Error",
            monospace = true,
        )

        KernelCheckStage.READY -> listOf(
            identityRow("uname -a", report.unameOutput),
            identityRow("/proc/version", report.procVersion),
            identityRow("/proc/cmdline", report.procCmdline),
        ) + buildIdentitySourceRows(report)
    }
}

internal fun buildIdentitySourceRows(
    report: KernelCheckReport,
): List<KernelCheckDetailRowModel> {
    return KernelIdentityField.entries.mapNotNull { field ->
        val fieldReads = report.identityReads.filter { it.field == field }
        if (fieldReads.isEmpty()) {
            return@mapNotNull null
        }

        val distinctValues = fieldReads.map { it.value }.distinct()
        KernelCheckDetailRowModel(
            label = "${field.label} across sources",
            value = when {
                distinctValues.size > 1 -> "Divergent"
                fieldReads.size > 1 -> "Consistent (${fieldReads.size})"
                else -> "Single source"
            },
            status = when {
                distinctValues.size > 1 -> DetectorStatus.danger()
                fieldReads.size > 1 -> DetectorStatus.allClear()
                else -> DetectorStatus.info(InfoKind.SUPPORT)
            },
            detail = fieldReads.joinToString(separator = "\n") { fieldRead ->
                "${fieldRead.label} = ${fieldRead.value}"
            },
            detailMonospace = true,
        )
    }
}

internal fun buildAnomalyRows(report: KernelCheckReport): List<KernelCheckDetailRowModel> {
    return when (report.stage) {
        KernelCheckStage.LOADING -> placeholderRows(
            labels = listOf("Kernel naming", "Boot parameters"),
            status = DetectorStatus.info(InfoKind.SUPPORT),
            value = "Pending",
        )

        KernelCheckStage.FAILED -> placeholderRows(
            labels = listOf("Kernel naming", "Boot parameters"),
            status = DetectorStatus.info(InfoKind.ERROR),
            value = "Error",
        )

        KernelCheckStage.READY -> if (report.dangerFindings.isEmpty()) {
            listOf(
                KernelCheckDetailRowModel(
                    label = "Anomalies",
                    value = if (report.nativeAvailable) "Clean" else "Limited",
                    status = if (report.nativeAvailable) {
                        DetectorStatus.allClear()
                    } else {
                        DetectorStatus.info(InfoKind.SUPPORT)
                    },
                    detail = if (report.nativeAvailable) {
                        "No hard kernel naming or boot-time anomaly surfaced."
                    } else {
                        "No hard kernel naming anomaly surfaced from fallback identity reads, but native boot/cmdline checks were unavailable."
                    },
                ),
            )
        } else {
            report.dangerFindings.map(::findingRowDanger)
        }
    }
}

internal fun buildBehaviorRows(report: KernelCheckReport): List<KernelCheckDetailRowModel> {
    return when (report.stage) {
        KernelCheckStage.LOADING -> placeholderRows(
            labels = listOf("CVE patch state", "kptr_restrict"),
            status = DetectorStatus.info(InfoKind.SUPPORT),
            value = "Pending",
        )

        KernelCheckStage.FAILED -> placeholderRows(
            labels = listOf("CVE patch state", "kptr_restrict"),
            status = DetectorStatus.info(InfoKind.ERROR),
            value = "Error",
        )

        KernelCheckStage.READY -> listOf(
            cvePatchRow(report),
            kptrRow(report),
        )
    }
}

internal fun buildMethodRows(report: KernelCheckReport): List<KernelCheckDetailRowModel> {
    return when (report.stage) {
        KernelCheckStage.LOADING -> placeholderMethodRows(
            DetectorStatus.info(InfoKind.SUPPORT),
            "Pending"
        )

        KernelCheckStage.FAILED -> placeholderMethodRows(
            DetectorStatus.info(InfoKind.ERROR),
            "Failed"
        )

        KernelCheckStage.READY -> report.methods.map { result ->
            KernelCheckDetailRowModel(
                label = result.label,
                value = result.summary,
                status = methodStatus(result),
                detail = result.detail,
                detailMonospace = true,
            )
        }
    }
}

internal fun buildScanRows(report: KernelCheckReport): List<KernelCheckDetailRowModel> {
    return when (report.stage) {
        KernelCheckStage.LOADING -> placeholderRows(
            labels = listOf(
                "Keyword families checked",
                "Cmdline rules checked",
                "Hard findings",
                "Info findings",
                "Identity sources",
                "Native library",
            ),
            status = DetectorStatus.info(InfoKind.SUPPORT),
            value = "Pending",
        )

        KernelCheckStage.FAILED -> placeholderRows(
            labels = listOf(
                "Keyword families checked",
                "Cmdline rules checked",
                "Hard findings",
                "Info findings",
                "Identity sources",
                "Native library",
            ),
            status = DetectorStatus.info(InfoKind.ERROR),
            value = "Error",
        )

        KernelCheckStage.READY -> listOf(
            KernelCheckDetailRowModel(
                label = "Keyword families checked",
                value = report.checkedKeywordCount.toString(),
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
            KernelCheckDetailRowModel(
                label = "Cmdline rules checked",
                value = report.checkedCmdlineRuleCount.toString(),
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
            KernelCheckDetailRowModel(
                label = "Hard findings",
                value = report.hardFindingCount.toString(),
                status = when {
                    report.hardFindingCount > 0 -> DetectorStatus.danger()
                    report.nativeAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            KernelCheckDetailRowModel(
                label = "Info findings",
                value = report.infoFindingCount.toString(),
                status = when {
                    report.hasReviewInfoIndicators -> DetectorStatus.warning()
                    report.infoFindingCount > 0 -> DetectorStatus.info(InfoKind.SUPPORT)
                    !report.nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.allClear()
                },
            ),
            KernelCheckDetailRowModel(
                label = "CVE patch state",
                value = report.cvePatchState.label,
                status = cvePatchStatus(report.cvePatchState),
            ),
            KernelCheckDetailRowModel(
                label = "Identity sources",
                value = identitySourceCount(report).toString(),
                status = if (identitySourceCount(report) > 0) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            KernelCheckDetailRowModel(
                label = "Native library",
                value = if (report.nativeAvailable) "Loaded" else "Unavailable",
                status = if (report.nativeAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
        )
    }
}

internal fun identityRow(
    label: String,
    value: String,
): KernelCheckDetailRowModel {
    return KernelCheckDetailRowModel(
        label = label,
        value = if (value.isNotBlank()) "Captured" else "Unavailable",
        status = if (value.isNotBlank()) DetectorStatus.allClear() else DetectorStatus.info(
            InfoKind.SUPPORT
        ),
        detail = value.ifBlank { "No readable data surfaced for $label." },
        detailMonospace = true,
    )
}

internal fun findingRowDanger(
    finding: KernelCheckFinding,
): KernelCheckDetailRowModel {
    return KernelCheckDetailRowModel(
        label = finding.label,
        value = finding.value,
        status = DetectorStatus.danger(),
        detail = finding.detail,
        detailMonospace = true,
    )
}

internal fun findingRowWarning(
    finding: KernelCheckFinding,
): KernelCheckDetailRowModel {
    return KernelCheckDetailRowModel(
        label = finding.label,
        value = finding.value,
        status = DetectorStatus.warning(),
        detail = finding.detail,
        detailMonospace = true,
    )
}

internal fun cvePatchRow(
    report: KernelCheckReport,
): KernelCheckDetailRowModel {
    return KernelCheckDetailRowModel(
        label = "CVE-2024-43093",
        value = report.cvePatchState.label,
        status = cvePatchStatus(report.cvePatchState),
        detail = report.cvePatchDetail ?: when (report.cvePatchState) {
            KernelCheckCvePatchState.UNPATCHED ->
                "Unicode ignorable codepoints still bypass the path filter."

            KernelCheckCvePatchState.PARTIALLY_PATCHED ->
                "ZWC is blocked, but at least one other ignorable codepoint still bypasses the path filter."

            KernelCheckCvePatchState.PATCHED ->
                "The tested bypass characters were blocked."

            KernelCheckCvePatchState.INCONCLUSIVE ->
                "The probe could not determine a stable patch state."
        },
        detailMonospace = false,
    )
}

internal fun kptrRow(
    report: KernelCheckReport,
): KernelCheckDetailRowModel {
    return when {
        report.kptrExposed -> {
            val finding = report.infoFindings.firstOrNull { it.kind == KernelCheckFindingKind.KPTR_EXPOSED }
            KernelCheckDetailRowModel(
                label = "kptr_restrict",
                value = "Exposed",
                status = DetectorStatus.warning(),
                detail = finding?.detail ?: "kptr_restrict appears disabled.",
            )
        }

        report.nativeAvailable -> {
            KernelCheckDetailRowModel(
                label = "kptr_restrict",
                value = "Protected",
                status = DetectorStatus.allClear(),
                detail = "Kernel addresses remained hidden during the native probe.",
            )
        }

        else -> {
            KernelCheckDetailRowModel(
                label = "kptr_restrict",
                value = "Unavailable",
                status = DetectorStatus.info(InfoKind.SUPPORT),
                detail = "Native /proc coverage was unavailable, so pointer exposure could not be verified.",
            )
        }
    }
}

internal fun placeholderRows(
    labels: List<String>,
    status: DetectorStatus,
    value: String,
    monospace: Boolean = false,
): List<KernelCheckDetailRowModel> {
    return labels.map { label ->
        KernelCheckDetailRowModel(
            label = label,
            value = value,
            status = status,
            detailMonospace = monospace,
        )
    }
}

internal fun placeholderMethodRows(
    status: DetectorStatus,
    value: String,
): List<KernelCheckDetailRowModel> {
    return KernelCheckMethod.entries.map { method ->
        KernelCheckDetailRowModel(
            label = method.label,
            value = value,
            status = status,
        )
    }
}

internal fun identitySourceCount(report: KernelCheckReport): Int {
    return listOf(report.unameOutput, report.procVersion).count { it.isNotBlank() }
}
