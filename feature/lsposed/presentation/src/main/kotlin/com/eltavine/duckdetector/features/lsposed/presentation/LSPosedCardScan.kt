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
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedReport
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedStage
import com.eltavine.duckdetector.features.lsposed.domain.hasReducedCoverage
import com.eltavine.duckdetector.features.lsposed.presentation.model.LSPosedDetailRowModel

internal fun buildScanRows(report: LSPosedReport): List<LSPosedDetailRowModel> {
    return when (report.stage) {
        LSPosedStage.LOADING -> placeholderRows(
            listOf(
                "Danger signals",
                "Review signals",
                "Class hits",
                "ClassLoader hits",
                "Bridge field hits",
                "Stack hits",
                "Callback hits",
                "Binder hits",
                "Runtime artifact hits",
                "Runtime artifacts availability",
                "Logcat hits",
                "Logcat availability",
                "Dirty policy hits",
                "Dirty policy availability",
                "Manager packages",
                "Module apps",
                "Native maps",
                "Native heap",
                "Package visibility",
            ),
            DetectorStatus.info(InfoKind.SUPPORT),
            "Pending",
        )

        LSPosedStage.FAILED -> placeholderRows(
            listOf(
                "Danger signals",
                "Review signals",
                "Class hits",
                "ClassLoader hits",
                "Bridge field hits",
                "Stack hits",
                "Callback hits",
                "Binder hits",
                "Runtime artifact hits",
                "Runtime artifacts availability",
                "Logcat hits",
                "Logcat availability",
                "Dirty policy hits",
                "Dirty policy availability",
                "Manager packages",
                "Module apps",
                "Native maps",
                "Native heap",
                "Package visibility",
            ),
            DetectorStatus.info(InfoKind.ERROR),
            "Error",
        )

        LSPosedStage.READY -> listOf(
            LSPosedDetailRowModel(
                label = "Danger signals",
                value = report.dangerSignalCount.toString(),
                status = when {
                    report.dangerSignalCount > 0 -> DetectorStatus.danger()
                    report.hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.allClear()
                },
            ),
            LSPosedDetailRowModel(
                label = "Review signals",
                value = report.warningSignalCount.toString(),
                status = when {
                    report.warningSignalCount > 0 -> DetectorStatus.warning()
                    report.hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.allClear()
                },
            ),
            LSPosedDetailRowModel(
                label = "Class hits",
                value = report.classHitCount.toString(),
                status = if (report.classHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
            ),
            LSPosedDetailRowModel(
                label = "ClassLoader hits",
                value = report.classLoaderHitCount.toString(),
                status = when {
                    report.signals.any {
                        it.id.startsWith("classloader_") &&
                                it.severity == LSPosedSignalSeverity.DANGER
                    } -> DetectorStatus.danger()

                    report.classLoaderHitCount > 0 -> DetectorStatus.warning()
                    else -> DetectorStatus.allClear()
                },
            ),
            LSPosedDetailRowModel(
                label = "Bridge field hits",
                value = report.bridgeFieldHitCount.toString(),
                status = if (report.bridgeFieldHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
            ),
            LSPosedDetailRowModel(
                label = "Stack hits",
                value = report.stackHitCount.toString(),
                status = if (report.stackHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
            ),
            LSPosedDetailRowModel(
                label = "Callback hits",
                value = report.callbackHitCount.toString(),
                status = if (report.callbackHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
            ),
            LSPosedDetailRowModel(
                label = "Binder hits",
                value = report.binderHitCount.toString(),
                status = if (report.binderHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
            ),
            LSPosedDetailRowModel(
                label = "Runtime artifact hits",
                value = report.runtimeArtifactHitCount.toString(),
                status = when {
                    report.signals.any {
                        it.id.startsWith("runtime_") &&
                                it.severity == LSPosedSignalSeverity.DANGER
                    } -> DetectorStatus.danger()

                    report.runtimeArtifactHitCount > 0 -> DetectorStatus.warning()
                    report.runtimeArtifactAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            LSPosedDetailRowModel(
                label = "Runtime artifacts availability",
                value = if (report.runtimeArtifactAvailable) "Checked" else "Unavailable",
                status = if (report.runtimeArtifactAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            LSPosedDetailRowModel(
                label = "Logcat hits",
                value = report.logcatHitCount.toString(),
                status = when {
                    report.signals.any {
                        it.id.startsWith("logcat_") &&
                                it.severity == LSPosedSignalSeverity.DANGER
                    } -> DetectorStatus.danger()

                    report.logcatHitCount > 0 -> DetectorStatus.warning()
                    report.logcatAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            LSPosedDetailRowModel(
                label = "Logcat availability",
                value = if (report.logcatAvailable) "Checked" else "Unavailable",
                status = if (report.logcatAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            LSPosedDetailRowModel(
                label = "Dirty policy hits",
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
                label = "Dirty policy availability",
                value = if (report.dirtyPolicyAvailable) "Checked" else "Unavailable",
                status = if (report.dirtyPolicyAvailable) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            LSPosedDetailRowModel(
                label = "Manager packages",
                value = report.managerPackageCount.toString(),
                status = if (report.managerPackageCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
            ),
            LSPosedDetailRowModel(
                label = "Module apps",
                value = report.moduleAppCount.toString(),
                status = if (report.moduleAppCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
            ),
            LSPosedDetailRowModel(
                label = "Native maps",
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
                label = "Native heap",
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
                label = "Package visibility",
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
