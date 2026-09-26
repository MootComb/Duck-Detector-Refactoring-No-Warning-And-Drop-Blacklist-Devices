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

package com.eltavine.duckdetector.features.lsposed.data.repository

import com.eltavine.duckdetector.features.lsposed.data.native.LSPosedNativeSnapshot
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedBridgeFieldProbeResult
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedClassLoaderProbeResult
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedDirtyPolicyProbeResult
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedHookCallbackProbeResult
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedLogcatProbeResult
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedRuntimeArtifactProbeResult
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedZygotePermissionProbeResult
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethod
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethodOutcome
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethodResult
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedPackageVisibility
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity

internal fun LSPosedRepository.buildMethods(
    classHitCount: Int,
    classLoaderResult: LSPosedClassLoaderProbeResult,
    bridgeFieldResult: LSPosedBridgeFieldProbeResult,
    managerPackageCount: Int,
    moduleAppCount: Int,
    packageVisibility: LSPosedPackageVisibility,
    stackHitCount: Int,
    hookCallbackResult: LSPosedHookCallbackProbeResult,
    binderHitCount: Int,
    zygotePermissionResult: LSPosedZygotePermissionProbeResult,
    runtimeArtifactResult: LSPosedRuntimeArtifactProbeResult,
    logcatResult: LSPosedLogcatProbeResult,
    dirtyPolicyResult: LSPosedDirtyPolicyProbeResult,
    nativeSnapshot: LSPosedNativeSnapshot,
    signals: List<LSPosedSignal>,
): List<LSPosedMethodResult> {
    val signalSummaryReducedCoverage = !nativeSnapshot.available ||
            !nativeSnapshot.mapsAvailable ||
            !nativeSnapshot.heapAvailable ||
            !zygotePermissionResult.available ||
            !runtimeArtifactResult.available ||
            !logcatResult.available ||
            packageVisibility != LSPosedPackageVisibility.FULL
    return listOf(
        LSPosedMethodResult(
            method = LSPosedMethod.CLASS_LOAD,
            summary = if (classHitCount > 0) "$classHitCount hit(s)" else "Clean",
            outcome = if (classHitCount > 0) LSPosedMethodOutcome.DETECTED else LSPosedMethodOutcome.CLEAN,
            detail = "Resolve known Xposed, libXposed, and LSPosed runtime classes through boot and app-facing class loaders.",
        ),
        LSPosedMethodResult(
            method = LSPosedMethod.CLASS_LOADER_CHAIN,
            summary = probeSummary(classLoaderResult.signals),
            outcome = probeOutcome(classLoaderResult.signals, available = true),
            detail = "Walks app-facing ClassLoader parent chains and flags loader names or chain depth that resemble LSPosed/Xposed injection.",
        ),
        LSPosedMethodResult(
            method = LSPosedMethod.XPOSED_BRIDGE_FIELDS,
            summary = probeSummary(bridgeFieldResult.signals),
            outcome = probeOutcome(bridgeFieldResult.signals, available = true),
            detail = "Reflects XposedBridge.disableHooks and XposedBridge.sHookedMethodCallbacks to confirm live bridge state rather than class residue alone.",
        ),
        LSPosedMethodResult(
            method = LSPosedMethod.PACKAGE_CATALOG,
            summary = when {
                managerPackageCount > 0 -> "$managerPackageCount installed"
                packageVisibility == LSPosedPackageVisibility.FULL -> "Clean"
                packageVisibility == LSPosedPackageVisibility.RESTRICTED -> "Restricted"
                else -> "Unknown"
            },
            outcome = when {
                managerPackageCount > 0 -> LSPosedMethodOutcome.WARNING
                packageVisibility == LSPosedPackageVisibility.FULL -> LSPosedMethodOutcome.CLEAN
                else -> LSPosedMethodOutcome.SUPPORT
            },
            detail = "Checks for LSPosed, LSPatch, EdXposed, Xposed installer, TaiChi, VirtualXposed, and common module-manager packages.",
        ),
        LSPosedMethodResult(
            method = LSPosedMethod.XPOSED_META_DATA,
            summary = when {
                moduleAppCount > 0 -> "$moduleAppCount module(s)"
                packageVisibility == LSPosedPackageVisibility.FULL -> "Clean"
                packageVisibility == LSPosedPackageVisibility.RESTRICTED -> "Restricted"
                else -> "Unknown"
            },
            outcome = when {
                moduleAppCount > 0 -> LSPosedMethodOutcome.WARNING
                packageVisibility == LSPosedPackageVisibility.FULL -> LSPosedMethodOutcome.CLEAN
                else -> LSPosedMethodOutcome.SUPPORT
            },
            detail = "Scans installed app manifest meta-data such as xposedmodule, xposedminversion, and xposedscope.",
        ),
        LSPosedMethodResult(
            method = LSPosedMethod.STACK_TRACE,
            summary = if (stackHitCount > 0) "$stackHitCount matched" else "Clean",
            outcome = if (stackHitCount > 0) LSPosedMethodOutcome.DETECTED else LSPosedMethodOutcome.CLEAN,
            detail = "Analyzes current-thread and synthetic throwable stacks for XposedBridge, LSPosedBridge, LSPHooker_, and related hook callback tokens.",
        ),
        LSPosedMethodResult(
            method = LSPosedMethod.HOOK_CALLBACKS,
            summary = probeSummary(hookCallbackResult.signals),
            outcome = probeOutcome(hookCallbackResult.signals, available = true),
            detail = "Checks whether the default uncaught-exception handler class points back to Xposed or LSPosed runtime code.",
        ),
        LSPosedMethodResult(
            method = LSPosedMethod.BINDER_BRIDGE,
            summary = if (binderHitCount > 0) "$binderHitCount hit(s)" else "Clean",
            outcome = if (binderHitCount > 0) LSPosedMethodOutcome.DETECTED else LSPosedMethodOutcome.CLEAN,
            detail = "Probes activity and serial Binder services for LSPosed bridge transaction behavior and descriptors.",
        ),
        LSPosedMethodResult(
            method = LSPosedMethod.ZYGOTE_PERMISSIONS,
            summary = when {
                !zygotePermissionResult.available -> "Unavailable"
                zygotePermissionResult.mismatchCount > 0 -> "${zygotePermissionResult.mismatchCount} mismatch(es)"
                zygotePermissionResult.auditedGrantCount > 0 -> "${zygotePermissionResult.auditedGrantCount} grant(s) clean"
                else -> "No mapped grants"
            },
            outcome = when {
                !zygotePermissionResult.available -> LSPosedMethodOutcome.SUPPORT
                zygotePermissionResult.mismatchCount > 0 -> LSPosedMethodOutcome.DETECTED
                zygotePermissionResult.auditedGrantCount > 0 -> LSPosedMethodOutcome.CLEAN
                else -> LSPosedMethodOutcome.SUPPORT
            },
            detail = "Compares granted app permissions against the zygote-assigned supplemental GIDs exposed through /proc/self/status. ${zygotePermissionResult.detail}",
        ),
        LSPosedMethodResult(
            method = LSPosedMethod.RUNTIME_ARTIFACTS,
            summary = runtimeProbeSummary(runtimeArtifactResult),
            outcome = probeOutcome(
                signals = runtimeArtifactResult.signals,
                available = runtimeArtifactResult.available,
            ),
            detail = runtimeArtifactResult.failureReason
                ?: "Scans /proc/self/net/unix, /proc/self/fd, and environment variables for LSPosed/Xposed runtime residue that leaks into the current app process.",
        ),
        LSPosedMethodResult(
            method = LSPosedMethod.LOGCAT_LEAKS,
            summary = runtimeProbeSummary(logcatResult),
            outcome = probeOutcome(
                signals = logcatResult.signals,
                available = logcatResult.available,
            ),
            detail = logcatResult.failureReason
                ?: "Samples recent logcat buffers for LSPosed tags, control messages, bridge traces, and org.lsposed.daemon process leakage without requesting extra permissions.",
        ),
        LSPosedMethodResult(
            method = LSPosedMethod.DIRTY_SEPOLICY,
            summary = dirtyPolicyResult.summary,
            outcome = dirtyPolicyResult.outcome,
            detail = dirtyPolicyResult.detail,
        ),
        LSPosedMethodResult(
            method = LSPosedMethod.NATIVE_MAPS,
            summary = when {
                nativeSnapshot.mapsHitCount > 0 -> "${nativeSnapshot.mapsHitCount} hit(s)"
                nativeSnapshot.mapsAvailable -> "Clean"
                else -> "Unavailable"
            },
            outcome = when {
                nativeSnapshot.mapsHitCount > 0 -> LSPosedMethodOutcome.DETECTED
                nativeSnapshot.mapsAvailable -> LSPosedMethodOutcome.CLEAN
                else -> LSPosedMethodOutcome.SUPPORT
            },
            detail = "Scans /proc/self/maps for LSPosed, XposedBridge, libXposed, LSPlant, EdXposed, and LSPatch runtime mappings.",
        ),
        LSPosedMethodResult(
            method = LSPosedMethod.NATIVE_HEAP,
            summary = when {
                nativeSnapshot.heapHitCount > 0 -> "${nativeSnapshot.heapHitCount} residual(s)"
                nativeSnapshot.heapAvailable -> "Clean"
                else -> "Unavailable"
            },
            outcome = when {
                nativeSnapshot.heapHitCount > 0 -> LSPosedMethodOutcome.DETECTED
                nativeSnapshot.heapAvailable -> LSPosedMethodOutcome.CLEAN
                else -> LSPosedMethodOutcome.SUPPORT
            },
            detail = "Samples readable Dalvik heap regions through /proc/self/mem for LSPosed and Xposed keyword residuals.",
        ),
        LSPosedMethodResult(
            method = LSPosedMethod.NATIVE_LIBRARY,
            summary = if (nativeSnapshot.available) "Loaded" else "Unavailable",
            outcome = if (nativeSnapshot.available) LSPosedMethodOutcome.CLEAN else LSPosedMethodOutcome.SUPPORT,
            detail = "JNI-backed maps and heap probes for LSPosed-specific runtime evidence.",
        ),
        LSPosedMethodResult(
            method = LSPosedMethod.SIGNAL_SUMMARY,
            summary = when {
                signals.any { it.severity == LSPosedSignalSeverity.DANGER } -> "${signals.count { it.severity == LSPosedSignalSeverity.DANGER }} strong"
                signals.isNotEmpty() -> "${signals.size} weak"
                signalSummaryReducedCoverage -> "Partial"
                else -> "Clean"
            },
            outcome = when {
                signals.any { it.severity == LSPosedSignalSeverity.DANGER } -> LSPosedMethodOutcome.DETECTED
                signals.isNotEmpty() -> LSPosedMethodOutcome.WARNING
                signalSummaryReducedCoverage -> LSPosedMethodOutcome.SUPPORT
                else -> LSPosedMethodOutcome.CLEAN
            },
            detail = "Direct runtime signals come from classes, stack traces, Binder bridges, and native traces; package-only signals are softer residue.",
        ),
    )
}

internal fun LSPosedRepository.probeSummary(
    signals: List<LSPosedSignal>,
): String {
    if (signals.isEmpty()) {
        return "Clean"
    }

    val dangerCount = signals.count { it.severity == LSPosedSignalSeverity.DANGER }
    val warningCount = signals.count { it.severity == LSPosedSignalSeverity.WARNING }
    return when {
        dangerCount > 0 && warningCount > 0 -> "${dangerCount + warningCount} hit(s)"
        dangerCount > 0 -> "$dangerCount hit(s)"
        else -> "$warningCount review"
    }
}

internal fun LSPosedRepository.runtimeProbeSummary(
    result: Any,
): String {
    return when (result) {
        is LSPosedRuntimeArtifactProbeResult -> when {
            !result.available -> "Unavailable"
            result.signals.isEmpty() -> "Clean"
            else -> probeSummary(result.signals)
        }

        is LSPosedLogcatProbeResult -> when {
            !result.available -> "Unavailable"
            result.signals.isEmpty() -> "Clean"
            else -> probeSummary(result.signals)
        }

        else -> "Unavailable"
    }
}

internal fun LSPosedRepository.probeOutcome(
    signals: List<LSPosedSignal>,
    available: Boolean,
): LSPosedMethodOutcome {
    return when {
        !available -> LSPosedMethodOutcome.SUPPORT
        signals.any { it.severity == LSPosedSignalSeverity.DANGER } -> LSPosedMethodOutcome.DETECTED
        signals.any { it.severity == LSPosedSignalSeverity.WARNING } -> LSPosedMethodOutcome.WARNING
        else -> LSPosedMethodOutcome.CLEAN
    }
}
