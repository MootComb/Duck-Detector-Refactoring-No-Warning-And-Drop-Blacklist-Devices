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
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedPackageVisibility
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedProbe
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedReport
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedStage
import com.eltavine.duckdetector.features.lsposed.domain.hasReducedCoverage
import com.eltavine.duckdetector.features.lsposed.presentation.model.LSPosedDetailRowModel
import com.eltavine.duckdetector.features.lsposed.presentation.model.LSPosedRowIcon

internal fun buildScanRows(report: LSPosedReport): List<LSPosedDetailRowModel> {
    return when (report.stage) {
        LSPosedStage.LOADING -> ScanRow.entries.map { it.placeholder(DetectorStatus.info(InfoKind.SUPPORT), "Pending") }

        LSPosedStage.FAILED -> ScanRow.entries.map { it.placeholder(DetectorStatus.info(InfoKind.ERROR), "Error") }

        LSPosedStage.READY -> listOf(
            LSPosedDetailRowModel(
                label = ScanRow.DANGER_SIGNALS.label,
                value = report.dangerSignalCount.toString(),
                status = when {
                    report.dangerSignalCount > 0 -> DetectorStatus.danger()
                    report.hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.allClear()
                },
            ),
            LSPosedDetailRowModel(
                label = ScanRow.REVIEW_SIGNALS.label,
                value = report.warningSignalCount.toString(),
                status = when {
                    report.warningSignalCount > 0 -> DetectorStatus.warning()
                    report.hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.allClear()
                },
            ),
            LSPosedDetailRowModel(
                label = ScanRow.CLASS_HITS.label,
                value = report.classHitCount.toString(),
                status = if (report.classHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
            ),
            LSPosedDetailRowModel(
                label = ScanRow.CLASS_LOADER_HITS.label,
                value = report.classLoaderHitCount.toString(),
                status = when {
                    report.signals.any {
                        it.probe == LSPosedProbe.CLASS_LOADER &&
                                it.severity == LSPosedSignalSeverity.DANGER
                    } -> DetectorStatus.danger()

                    report.classLoaderHitCount > 0 -> DetectorStatus.warning()
                    else -> DetectorStatus.allClear()
                },
            ),
            LSPosedDetailRowModel(
                label = ScanRow.BRIDGE_FIELD_HITS.label,
                icon = ScanRow.BRIDGE_FIELD_HITS.icon,
                value = report.bridgeFieldHitCount.toString(),
                status = if (report.bridgeFieldHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
            ),
            LSPosedDetailRowModel(
                label = ScanRow.STACK_HITS.label,
                icon = ScanRow.STACK_HITS.icon,
                value = report.stackHitCount.toString(),
                status = if (report.stackHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
            ),
            LSPosedDetailRowModel(
                label = ScanRow.CALLBACK_HITS.label,
                value = report.callbackHitCount.toString(),
                status = if (report.callbackHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
            ),
            LSPosedDetailRowModel(
                label = ScanRow.BINDER_HITS.label,
                value = report.binderHitCount.toString(),
                status = if (report.binderHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
            ),
            LSPosedDetailRowModel(
                label = ScanRow.RUNTIME_ARTIFACT_HITS.label,
                value = report.runtimeArtifactHitCount.toString(),
                status = when {
                    report.signals.any {
                        it.probe == LSPosedProbe.RUNTIME_ARTIFACT &&
                                it.severity == LSPosedSignalSeverity.DANGER
                    } -> DetectorStatus.danger()

                    report.runtimeArtifactHitCount > 0 -> DetectorStatus.warning()
                    report.runtimeArtifactAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            LSPosedDetailRowModel(
                label = ScanRow.RUNTIME_ARTIFACTS_AVAILABILITY.label,
                value = if (report.runtimeArtifactAvailable) "Checked" else "Unavailable",
                status = if (report.runtimeArtifactAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            LSPosedDetailRowModel(
                label = ScanRow.LOGCAT_HITS.label,
                value = report.logcatHitCount.toString(),
                status = when {
                    report.signals.any {
                        it.probe == LSPosedProbe.LOGCAT &&
                                it.severity == LSPosedSignalSeverity.DANGER
                    } -> DetectorStatus.danger()

                    report.logcatHitCount > 0 -> DetectorStatus.warning()
                    report.logcatAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            LSPosedDetailRowModel(
                label = ScanRow.LOGCAT_AVAILABILITY.label,
                value = if (report.logcatAvailable) "Checked" else "Unavailable",
                status = if (report.logcatAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            LSPosedDetailRowModel(
                label = ScanRow.DIRTY_POLICY_HITS.label,
                icon = ScanRow.DIRTY_POLICY_HITS.icon,
                value = report.policySignalCount.toString(),
                status = when {
                    report.signals.any {
                        it.group == LSPosedSignalGroup.POLICY &&
                            it.severity == LSPosedSignalSeverity.DANGER
                    } -> DetectorStatus.danger()

                    report.policySignalCount > 0 -> DetectorStatus.warning()
                    report.dirtyPolicyAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            LSPosedDetailRowModel(
                label = ScanRow.DIRTY_POLICY_AVAILABILITY.label,
                icon = ScanRow.DIRTY_POLICY_AVAILABILITY.icon,
                value = if (report.dirtyPolicyAvailable) "Checked" else "Unavailable",
                status = if (report.dirtyPolicyAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            LSPosedDetailRowModel(
                label = ScanRow.MANAGER_PACKAGES.label,
                icon = ScanRow.MANAGER_PACKAGES.icon,
                value = report.managerPackageCount.toString(),
                status = if (report.managerPackageCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
            ),
            LSPosedDetailRowModel(
                label = ScanRow.MODULE_APPS.label,
                value = report.moduleAppCount.toString(),
                status = if (report.moduleAppCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
            ),
            LSPosedDetailRowModel(
                label = ScanRow.NATIVE_MAPS.label,
                value = if (report.nativeMapsAvailable || report.nativeMapsHitCount > 0) {
                    report.nativeMapsHitCount.toString()
                } else {
                    "N/A"
                },
                status = when {
                    report.nativeMapsHitCount > 0 -> DetectorStatus.danger()
                    report.nativeMapsAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            LSPosedDetailRowModel(
                label = ScanRow.NATIVE_HEAP.label,
                icon = ScanRow.NATIVE_HEAP.icon,
                value = if (report.nativeHeapAvailable || report.nativeHeapHitCount > 0) {
                    "${report.nativeHeapHitCount}/${report.nativeHeapScannedRegions}"
                } else {
                    "N/A"
                },
                status = when {
                    report.nativeHeapHitCount > 0 -> DetectorStatus.danger()
                    report.nativeHeapAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            LSPosedDetailRowModel(
                label = ScanRow.PACKAGE_VISIBILITY.label,
                icon = ScanRow.PACKAGE_VISIBILITY.icon,
                value = visibilityLabel(report.packageVisibility),
                status = when (report.packageVisibility) {
                    LSPosedPackageVisibility.FULL -> DetectorStatus.allClear()
                    LSPosedPackageVisibility.RESTRICTED -> DetectorStatus.info(InfoKind.SUPPORT)
                    LSPosedPackageVisibility.UNKNOWN -> DetectorStatus.info(InfoKind.ERROR)
                },
            ),
        )
    }
}

/** The scan section's rows, in order, with the icon each row shows. */
private enum class ScanRow(val label: String, val icon: LSPosedRowIcon? = null) {
    DANGER_SIGNALS("Danger signals"),
    REVIEW_SIGNALS("Review signals"),
    CLASS_HITS("Class hits"),
    CLASS_LOADER_HITS("ClassLoader hits"),
    BRIDGE_FIELD_HITS("Bridge field hits", LSPosedRowIcon.BRIDGE),
    STACK_HITS("Stack hits", LSPosedRowIcon.HOOK),
    CALLBACK_HITS("Callback hits"),
    BINDER_HITS("Binder hits"),
    RUNTIME_ARTIFACT_HITS("Runtime artifact hits"),
    RUNTIME_ARTIFACTS_AVAILABILITY("Runtime artifacts availability"),
    LOGCAT_HITS("Logcat hits"),
    LOGCAT_AVAILABILITY("Logcat availability"),
    DIRTY_POLICY_HITS("Dirty policy hits", LSPosedRowIcon.POLICY),
    DIRTY_POLICY_AVAILABILITY("Dirty policy availability", LSPosedRowIcon.POLICY),
    MANAGER_PACKAGES("Manager packages", LSPosedRowIcon.PACKAGE),
    MODULE_APPS("Module apps"),
    NATIVE_MAPS("Native maps"),
    NATIVE_HEAP("Native heap", LSPosedRowIcon.MEMORY),
    PACKAGE_VISIBILITY("Package visibility", LSPosedRowIcon.PACKAGE),
    ;

    fun placeholder(status: DetectorStatus, value: String) =
        LSPosedDetailRowModel(label = label, value = value, status = status, icon = icon)
}
