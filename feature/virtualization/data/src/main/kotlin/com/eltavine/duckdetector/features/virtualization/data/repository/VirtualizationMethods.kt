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

package com.eltavine.duckdetector.features.virtualization.data.repository

import com.eltavine.duckdetector.capability.earlypreload.data.EarlyVirtualizationPreloadResult
import com.eltavine.duckdetector.capability.helperprocess.data.SacrificialSyscallPackResult
import com.eltavine.duckdetector.capability.helperprocess.data.VirtualizationRemoteSnapshot
import com.eltavine.duckdetector.capability.helperprocess.data.VirtualizationTrapResult
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import com.eltavine.duckdetector.features.virtualization.data.probes.DexPathProbeResult
import com.eltavine.duckdetector.features.virtualization.data.probes.UidIdentityProbeResult
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationHostAppProbeResult
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationServiceProbeResult
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationMethodOutcome
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationMethodResult
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignal
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity

internal fun buildMethods(
    propertySignals: List<VirtualizationSignal>,
    dexPathResult: DexPathProbeResult,
    uidIdentityResult: UidIdentityProbeResult,
    runtimeSignals: List<VirtualizationSignal>,
    graphicsSignals: List<VirtualizationSignal>,
    translationSignals: List<VirtualizationSignal>,
    preloadSignals: List<VirtualizationSignal>,
    preloadResult: EarlyVirtualizationPreloadResult,
    crossProcessSignals: List<VirtualizationSignal>,
    isolatedSignals: List<VirtualizationSignal>,
    remoteSnapshot: VirtualizationRemoteSnapshot,
    isolatedSnapshot: VirtualizationRemoteSnapshot,
    hostAppResult: VirtualizationHostAppProbeResult,
    nativeTimingTrap: VirtualizationTrapResult,
    nativeSyscallParityTrap: VirtualizationTrapResult,
    asmCounterTrap: VirtualizationTrapResult,
    asmRawSyscallTrap: VirtualizationTrapResult,
    syscallPackResult: SacrificialSyscallPackResult,
    serviceResult: VirtualizationServiceProbeResult,
): List<VirtualizationMethodResult> {
    val nativeTrapResults = listOf(nativeTimingTrap, nativeSyscallParityTrap)
    val asmTrapResults = listOf(asmCounterTrap, asmRawSyscallTrap)
    return listOf(
        VirtualizationMethodResult(
            label = "Properties and build",
            summary = if (propertySignals.isEmpty() && !serviceResult.available) "Partial" else methodSummary(propertySignals),
            outcome = if (propertySignals.isEmpty() && !serviceResult.available) {
                VirtualizationMethodOutcome.SUPPORT
            } else {
                methodOutcome(propertySignals)
            },
            detail = buildString {
                append("Checks system properties, Build fields, and ServiceManager guest services.\n")
                serviceResult.failure?.let { failure ->
                    append("ServiceManager lookups failed with ")
                    append(failure)
                    append(", so guest services may be missing from this result.")
                } ?: append("Listed services: ${serviceResult.listedServiceCount}")
            },
        ),
        VirtualizationMethodResult(
            label = "Dex and classpath",
            summary = if (dexPathResult.signals.isEmpty()) "Clean" else methodSummary(
                dexPathResult.signals
            ),
            outcome = methodOutcome(dexPathResult.signals),
            detail = buildString {
                append("Class path entries: ")
                append(dexPathResult.entryCount)
                if (dexPathResult.classPathEntries.isNotEmpty()) {
                    append("\n")
                    append(dexPathResult.classPathEntries.joinToString(separator = "\n"))
                }
            },
        ),
        VirtualizationMethodResult(
            label = "UID identity",
            summary = if (uidIdentityResult.signals.isEmpty()) "Clean" else methodSummary(
                uidIdentityResult.signals
            ),
            outcome = methodOutcome(uidIdentityResult.signals),
            detail = buildString {
                append("uid=")
                append(uidIdentityResult.uid)
                append(" applicationUid=")
                append(uidIdentityResult.applicationUid)
                append("\nprocessName=")
                append(uidIdentityResult.processName)
                append("\nuidName=")
                append(uidIdentityResult.uidName.ifBlank { "<empty>" })
                append("\npackagesForUid=\n")
                append(
                    uidIdentityResult.packagesForUid.joinToString(separator = "\n")
                        .ifBlank { "<empty>" })
            },
        ),
        VirtualizationMethodResult(
            label = "Runtime artifacts",
            summary = if (runtimeSignals.isEmpty()) "Clean" else methodSummary(runtimeSignals),
            outcome = if (runtimeSignals.isEmpty()) VirtualizationMethodOutcome.CLEAN else methodOutcome(
                runtimeSignals
            ),
            detail = "Collects /proc/self/maps, /proc/self/fd, mountinfo, direct device nodes, and raw mount anchors from the current process.",
        ),
        VirtualizationMethodResult(
            label = "Graphics renderer",
            summary = if (graphicsSignals.isEmpty()) "Clean" else methodSummary(graphicsSignals),
            outcome = if (graphicsSignals.isEmpty()) VirtualizationMethodOutcome.CLEAN else methodOutcome(
                graphicsSignals
            ),
            detail = "Builds an off-screen EGL context and inspects GL_VENDOR, GL_RENDERER, and GL_VERSION.",
        ),
        VirtualizationMethodResult(
            label = "Native bridge",
            summary = methodSummary(translationSignals),
            outcome = methodOutcome(translationSignals),
            detail = "Checks ART native bridge properties and translated runtime libraries such as libhoudini, libnb, and libndk_translation.",
        ),
        VirtualizationMethodResult(
            label = "Startup preload",
            summary = when {
                !preloadResult.hasRun -> "Unavailable"
                preloadSignals.isEmpty() -> "Clean"
                else -> methodSummary(preloadSignals)
            },
            outcome = when {
                !preloadResult.hasRun -> VirtualizationMethodOutcome.SUPPORT
                preloadSignals.isEmpty() -> VirtualizationMethodOutcome.CLEAN
                else -> methodOutcome(preloadSignals)
            },
            detail = preloadResult.details,
        ),
        VirtualizationMethodResult(
            label = "Cross-process consistency",
            summary = when {
                !remoteSnapshot.available -> "Unavailable"
                crossProcessSignals.isEmpty() -> "Clean"
                else -> "${crossProcessSignals.size} drift hit(s)"
            },
            outcome = when {
                !remoteSnapshot.available -> VirtualizationMethodOutcome.SUPPORT
                crossProcessSignals.isEmpty() -> VirtualizationMethodOutcome.CLEAN
                else -> methodOutcome(crossProcessSignals)
            },
            detail = remoteSnapshot.errorDetail.ifBlank {
                "Compares regular helper-process paths, mount anchors, and artifact sets against the main process and startup preload."
            },
        ),
        VirtualizationMethodResult(
            label = "Isolated-process consistency",
            summary = when {
                !isolatedSnapshot.available -> "Unavailable"
                isolatedSignals.isEmpty() -> "Clean"
                else -> "${isolatedSignals.size} drift hit(s)"
            },
            outcome = when {
                !isolatedSnapshot.available -> VirtualizationMethodOutcome.SUPPORT
                isolatedSignals.isEmpty() -> VirtualizationMethodOutcome.CLEAN
                else -> methodOutcome(isolatedSignals)
            },
            detail = isolatedSnapshot.errorDetail.ifBlank {
                "Compares the isolated process against the main process for host residue, namespace drift, and anchor-mount divergence."
            },
        ),
        VirtualizationMethodResult(
            label = "Host apps",
            summary = when {
                hostAppResult.findings.isNotEmpty() -> "${hostAppResult.findings.size} corroborating app(s)"
                hostAppResult.packageVisibility == InstalledPackageVisibility.RESTRICTED -> "Scoped"
                hostAppResult.packageVisibility == InstalledPackageVisibility.UNKNOWN -> "Unavailable"
                else -> "Clean"
            },
            outcome = when {
                hostAppResult.findings.isNotEmpty() -> VirtualizationMethodOutcome.INFO
                hostAppResult.packageVisibility != InstalledPackageVisibility.FULL -> VirtualizationMethodOutcome.SUPPORT
                else -> VirtualizationMethodOutcome.CLEAN
            },
            detail = hostAppResult.issues.joinToString(separator = "\n").ifBlank {
                "Checks known virtualization host packages via PackageManager, FUSE paths, native /data stats, and special paths."
            },
        ),
        VirtualizationMethodResult(
            label = "Native honeypots",
            summary = honeypotSummary(nativeTrapResults),
            outcome = honeypotOutcome(nativeTrapResults),
            detail = listOf(nativeTimingTrap.detail, nativeSyscallParityTrap.detail)
                .filter { it.isNotBlank() }
                .joinToString(separator = "\n\n"),
        ),
        VirtualizationMethodResult(
            label = "ASM honeypots",
            summary = honeypotSummary(asmTrapResults),
            outcome = honeypotOutcome(asmTrapResults),
            detail = listOf(asmCounterTrap.detail, asmRawSyscallTrap.detail)
                .filter { it.isNotBlank() }
                .joinToString(separator = "\n\n"),
        ),
        VirtualizationMethodResult(
            label = "Sacrificial syscall pack",
            summary = syscallPackSummary(syscallPackResult),
            outcome = syscallPackOutcome(syscallPackResult),
            detail = buildString {
                append(syscallPackResult.detail)
                if (syscallPackResult.items.isNotEmpty()) {
                    if (isNotEmpty()) append("\n\n")
                    append(
                        syscallPackResult.items.joinToString(separator = "\n\n") { item ->
                            buildString {
                                append(item.label)
                                append(": ")
                                append(item.suspiciousAttempts)
                                append("/")
                                append(item.completedAttempts)
                                append(" suspicious")
                                if (item.detail.isNotBlank()) {
                                    append("\n")
                                    append(item.detail)
                                }
                            }
                        },
                    )
                }
            }.trim(),
        ),
    )
}

private fun methodSummary(signals: List<VirtualizationSignal>): String {
    return when {
        signals.any { it.severity == VirtualizationSignalSeverity.DANGER } -> "${signals.size} hit(s)"
        signals.any { it.severity == VirtualizationSignalSeverity.WARNING } -> "${signals.size} hit(s)"
        signals.any { it.severity == VirtualizationSignalSeverity.INFO } -> "${signals.size} info hit(s)"
        else -> "Clean"
    }
}

private fun methodOutcome(signals: List<VirtualizationSignal>): VirtualizationMethodOutcome {
    return when {
        signals.any { it.severity == VirtualizationSignalSeverity.DANGER } -> VirtualizationMethodOutcome.DANGER
        signals.any { it.severity == VirtualizationSignalSeverity.WARNING } -> VirtualizationMethodOutcome.WARNING
        signals.any { it.severity == VirtualizationSignalSeverity.INFO } -> VirtualizationMethodOutcome.INFO
        else -> VirtualizationMethodOutcome.CLEAN
    }
}

private fun honeypotSummary(results: List<VirtualizationTrapResult>): String {
    val supported = results.filter { it.supported }
    return when {
        supported.isEmpty() -> "Unsupported"
        supported.any { it.suspicious } -> "${supported.count { it.suspicious }} suspicious trap(s)"
        supported.all { it.clean } -> "Clean"
        else -> "Partial"
    }
}

private fun honeypotOutcome(results: List<VirtualizationTrapResult>): VirtualizationMethodOutcome {
    val supported = results.filter { it.supported }
    return when {
        supported.isEmpty() -> VirtualizationMethodOutcome.SUPPORT
        supported.any { it.suspicious } -> VirtualizationMethodOutcome.WARNING
        supported.all { it.clean } -> VirtualizationMethodOutcome.CLEAN
        else -> VirtualizationMethodOutcome.SUPPORT
    }
}

private fun syscallPackSummary(result: SacrificialSyscallPackResult): String {
    return when {
        !result.supported -> "Unsupported"
        result.suspiciousItems.isNotEmpty() -> "${result.suspiciousItems.size} suspicious syscall(s)"
        result.items.isNotEmpty() && result.items.all { it.clean } -> "Clean"
        else -> "Partial"
    }
}

private fun syscallPackOutcome(result: SacrificialSyscallPackResult): VirtualizationMethodOutcome {
    return when {
        !result.supported -> VirtualizationMethodOutcome.SUPPORT
        result.suspiciousItems.isNotEmpty() -> VirtualizationMethodOutcome.WARNING
        result.items.isNotEmpty() && result.items.all { it.clean } -> VirtualizationMethodOutcome.CLEAN
        else -> VirtualizationMethodOutcome.SUPPORT
    }
}
