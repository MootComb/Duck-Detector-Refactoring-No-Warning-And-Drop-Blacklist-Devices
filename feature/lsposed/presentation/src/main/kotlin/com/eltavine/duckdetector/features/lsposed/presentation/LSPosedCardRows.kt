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
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethod
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethodOutcome
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethodResult
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedPackageVisibility
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedProbe
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedReport
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedStage
import com.eltavine.duckdetector.features.lsposed.presentation.model.LSPosedDetailRowModel
import com.eltavine.duckdetector.features.lsposed.presentation.model.LSPosedRowIcon

internal fun buildRowsForGroup(
    report: LSPosedReport,
    group: LSPosedSignalGroup,
    fallbackLabel: String,
): List<LSPosedDetailRowModel> {
    return when (report.stage) {
        LSPosedStage.LOADING -> listOf(
            LSPosedDetailRowModel(
                label = fallbackLabel,
                value = "Pending",
                status = DetectorStatus.info(InfoKind.SUPPORT),
                icon = group.fallbackIcon(),
            ),
        )

        LSPosedStage.FAILED -> listOf(
            LSPosedDetailRowModel(
                label = fallbackLabel,
                value = "Error",
                status = DetectorStatus.info(InfoKind.ERROR),
                icon = group.fallbackIcon(),
            ),
        )

        LSPosedStage.READY -> {
            val rows = report.signals
                .filter { it.group == group }
                .map(::signalRow)
            if (rows.isNotEmpty()) {
                rows
            } else if (report.sectionUnavailable(group)) {
                listOf(
                    LSPosedDetailRowModel(
                        label = fallbackLabel,
                        value = if (group == LSPosedSignalGroup.PACKAGES) {
                            visibilityLabel(report.packageVisibility)
                        } else {
                            "Unavailable"
                        },
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                        detail = "This LSPosed evidence slice was unavailable or scoped, so it is not treated as clean.",
                        icon = group.fallbackIcon(),
                    ),
                )
            } else {
                listOf(
                    LSPosedDetailRowModel(
                        label = fallbackLabel,
                        value = "Clean",
                        status = DetectorStatus.allClear(),
                        detail = "No signal surfaced in this LSPosed evidence slice.",
                        icon = group.fallbackIcon(),
                    ),
                )
            }
        }
    }
}

private fun signalRow(signal: LSPosedSignal): LSPosedDetailRowModel {
    return LSPosedDetailRowModel(
        label = signal.label,
        value = signal.value,
        status = signalStatus(signal),
        detail = signal.detail,
        detailMonospace = signal.detailMonospace,
        icon = signal.probe.rowIcon(),
    )
}

private fun signalStatus(signal: LSPosedSignal): DetectorStatus {
    return when (signal.severity) {
        LSPosedSignalSeverity.DANGER -> DetectorStatus.danger()
        LSPosedSignalSeverity.WARNING -> DetectorStatus.warning()
    }
}

private fun LSPosedReport.sectionUnavailable(group: LSPosedSignalGroup): Boolean {
    return when (group) {
        LSPosedSignalGroup.NATIVE -> !nativeAvailable || !nativeMapsAvailable || !nativeHeapAvailable
        LSPosedSignalGroup.PACKAGES -> packageVisibility != LSPosedPackageVisibility.FULL
        LSPosedSignalGroup.RUNTIME -> !runtimeArtifactAvailable || !logcatAvailable
        LSPosedSignalGroup.POLICY -> !dirtyPolicyAvailable
        LSPosedSignalGroup.BINDER -> false
    }
}

internal fun buildMethodRows(report: LSPosedReport): List<LSPosedDetailRowModel> {
    return when (report.stage) {
        LSPosedStage.LOADING -> placeholderMethodRows(
            DetectorStatus.info(InfoKind.SUPPORT),
            "Pending"
        )

        LSPosedStage.FAILED -> placeholderMethodRows(
            DetectorStatus.info(InfoKind.ERROR),
            "Error"
        )

        LSPosedStage.READY -> report.methods.map { method ->
            LSPosedDetailRowModel(
                label = method.label,
                value = method.summary,
                status = methodStatus(method),
                detail = method.detail,
                detailMonospace = false,
                icon = method.method.rowIcon(),
            )
        }
    }
}

private fun placeholderMethodRows(
    status: DetectorStatus,
    value: String,
): List<LSPosedDetailRowModel> {
    return LSPosedMethod.entries.map { method ->
        LSPosedDetailRowModel(
            label = method.label,
            value = value,
            status = status,
            icon = method.rowIcon(),
        )
    }
}

private fun LSPosedProbe.rowIcon(): LSPosedRowIcon? = when (this) {
    LSPosedProbe.BINDER,
    LSPosedProbe.BRIDGE_FIELD -> LSPosedRowIcon.BRIDGE
    LSPosedProbe.PACKAGE -> LSPosedRowIcon.PACKAGE
    LSPosedProbe.NATIVE_TRACE -> LSPosedRowIcon.MEMORY
    LSPosedProbe.DIRTY_POLICY -> LSPosedRowIcon.POLICY
    LSPosedProbe.CLASS,
    LSPosedProbe.STACK -> LSPosedRowIcon.HOOK
    LSPosedProbe.CLASS_LOADER,
    LSPosedProbe.HOOK_CALLBACK,
    LSPosedProbe.ZYGOTE_PERMISSION,
    LSPosedProbe.RUNTIME_ARTIFACT,
    LSPosedProbe.LOGCAT -> null
}

private fun LSPosedSignalGroup.fallbackIcon(): LSPosedRowIcon? = when (this) {
    LSPosedSignalGroup.PACKAGES -> LSPosedRowIcon.PACKAGE
    LSPosedSignalGroup.POLICY -> LSPosedRowIcon.POLICY
    LSPosedSignalGroup.NATIVE,
    LSPosedSignalGroup.RUNTIME,
    LSPosedSignalGroup.BINDER -> null
}

private fun LSPosedMethod.rowIcon(): LSPosedRowIcon? = when (this) {
    LSPosedMethod.XPOSED_BRIDGE_FIELDS,
    LSPosedMethod.BINDER_BRIDGE -> LSPosedRowIcon.BRIDGE
    LSPosedMethod.PACKAGE_CATALOG -> LSPosedRowIcon.PACKAGE
    LSPosedMethod.NATIVE_HEAP -> LSPosedRowIcon.MEMORY
    LSPosedMethod.DIRTY_SEPOLICY -> LSPosedRowIcon.POLICY
    LSPosedMethod.XPOSED_META_DATA,
    LSPosedMethod.STACK_TRACE -> LSPosedRowIcon.HOOK
    else -> null
}

private fun methodStatus(method: LSPosedMethodResult): DetectorStatus {
    return when (method.outcome) {
        LSPosedMethodOutcome.CLEAN -> DetectorStatus.allClear()
        LSPosedMethodOutcome.WARNING -> DetectorStatus.warning()
        LSPosedMethodOutcome.DETECTED -> DetectorStatus.danger()
        LSPosedMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
    }
}
