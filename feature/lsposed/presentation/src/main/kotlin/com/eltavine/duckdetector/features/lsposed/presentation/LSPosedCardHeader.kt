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
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedStage
import com.eltavine.duckdetector.features.lsposed.domain.hasReducedCoverage
import com.eltavine.duckdetector.features.lsposed.presentation.model.LSPosedHeaderFact
import com.eltavine.duckdetector.features.lsposed.presentation.model.LSPosedHeaderFactModel

internal fun buildSubtitle(report: LSPosedReport): String {
    return when (report.stage) {
        LSPosedStage.LOADING -> "class + classloader + bridge fields + callbacks + runtime + logcat + binder + zygote gids + policy + native"
        LSPosedStage.FAILED -> "local LSPosed/Xposed scan failed"
        LSPosedStage.READY -> {
            buildList {
                add("${report.managerPackageCount} manager")
                add("${report.moduleAppCount} module")
                add("${report.nativeTraceCount} native")
                if (report.dirtyPolicyAvailable || report.policySignalCount > 0) {
                    add("${report.policySignalCount} policy")
                }
            }.joinToString(" · ")
        }
    }
}

internal fun buildVerdict(report: LSPosedReport): String {
    return when (report.stage) {
        LSPosedStage.LOADING -> "Scanning LSPosed/Xposed runtime and residue"
        LSPosedStage.FAILED -> "LSPosed scan failed"
        LSPosedStage.READY -> when {
            report.lsposedPolicyRuleExposed -> "Dirty SELinux policy exposes LSPosed rule"
            report.hasDangerSignals -> "${report.dangerSignalCount} high-risk LSPosed signal(s)"
            report.hasPolicySignals() -> "Dirty SELinux policy signal(s)"
            report.hasWarningSignals -> "${report.warningSignalCount} LSPosed residue signal(s)"
            report.hasReducedCoverage() -> "LSPosed scan has reduced coverage"
            else -> "No LSPosed/Xposed runtime signal"
        }
    }
}

internal fun buildSummary(report: LSPosedReport): String {
    return when (report.stage) {
        LSPosedStage.LOADING ->
            "Class loading, ClassLoader chains, XposedBridge fields, callbacks, package metadata, stack traces, Binder bridges, zygote permission GID audits, runtime artifacts, logcat leaks, and LSPosed-specific native traces are collecting local evidence."

        LSPosedStage.FAILED ->
            report.errorMessage
                ?: "LSPosed detection failed before evidence could be assembled."

        LSPosedStage.READY -> when {
            report.hasDangerSignals ->
                "Binder bridge replies, loaded Xposed classes, XposedBridge fields, callback handlers, runtime artifacts, logcat leaks, zygote permission GID mismatches, dirty SELinux policy rules, stack trace signatures, or native LSPosed keywords point to active hook-framework presence rather than passive install residue."

            report.hasWarningSignals ->
                "Installed managers, deep ClassLoader chains, environment residue, dirty SELinux policy drift, or pattern-only logcat traces were found, but the current process did not expose enough stronger runtime evidence to treat the framework as confirmed active here."

            report.hasReducedCoverage() ->
                "No LSPosed/Xposed signal surfaced from the available probes, but at least one runtime, package, logcat, or native evidence path was unavailable."

            else ->
                "No Xposed class loading, ClassLoader, callback, Binder bridge, runtime artifact, logcat, stack, maps, or heap traces surfaced in the current app process."
        }
    }
}

internal fun buildHeaderFacts(report: LSPosedReport): List<LSPosedHeaderFactModel> {
    return when (report.stage) {
        LSPosedStage.LOADING -> placeholderFacts(
            "Pending",
            DetectorStatus.info(InfoKind.SUPPORT)
        )

        LSPosedStage.FAILED -> placeholderFacts("Error", DetectorStatus.info(InfoKind.ERROR))
        LSPosedStage.READY -> listOf(
            LSPosedHeaderFactModel(
                fact = LSPosedHeaderFact.CRITICAL,
                value = countLabel(report.dangerSignalCount, report.hasReducedCoverage()),
                status = when {
                    report.dangerSignalCount > 0 -> DetectorStatus.danger()
                    report.hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.allClear()
                },
            ),
            LSPosedHeaderFactModel(
                fact = LSPosedHeaderFact.REVIEW,
                value = countLabel(report.warningSignalCount, report.hasReducedCoverage()),
                status = when {
                    report.warningSignalCount > 0 -> DetectorStatus.warning()
                    report.hasReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.allClear()
                },
            ),
            LSPosedHeaderFactModel(
                fact = LSPosedHeaderFact.BRIDGE,
                value = if (report.binderHitCount > 0) report.binderHitCount.toString() else "Clean",
                status = if (report.binderHitCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
            ),
            LSPosedHeaderFactModel(
                fact = LSPosedHeaderFact.PACKAGES,
                value = when {
                    report.packageSignalCount > 0 -> report.packageSignalCount.toString()
                    report.packageVisibility == LSPosedPackageVisibility.FULL -> "Clean"
                    else -> visibilityLabel(report.packageVisibility)
                },
                status = when {
                    report.packageSignalCount > 0 -> DetectorStatus.warning()
                    report.packageVisibility == LSPosedPackageVisibility.FULL -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
        )
    }
}

private fun placeholderFacts(
    value: String,
    status: DetectorStatus,
): List<LSPosedHeaderFactModel> {
    return listOf(
        LSPosedHeaderFactModel(LSPosedHeaderFact.CRITICAL, value, status),
        LSPosedHeaderFactModel(LSPosedHeaderFact.REVIEW, value, status),
        LSPosedHeaderFactModel(LSPosedHeaderFact.BRIDGE, value, status),
        LSPosedHeaderFactModel(LSPosedHeaderFact.PACKAGES, value, status),
    )
}

private fun countLabel(count: Int, reducedCoverage: Boolean = false): String {
    return when {
        count > 0 -> count.toString()
        reducedCoverage -> "N/A"
        else -> "None"
    }
}

private fun LSPosedReport.hasPolicySignals(): Boolean {
    return policySignalCount > 0
}

internal fun visibilityLabel(
    visibility: LSPosedPackageVisibility,
): String {
    return when (visibility) {
        LSPosedPackageVisibility.FULL -> "Full"
        LSPosedPackageVisibility.RESTRICTED -> "Restricted"
        LSPosedPackageVisibility.UNKNOWN -> "Unknown"
    }
}
