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

import android.content.Context
import com.eltavine.duckdetector.capability.earlypreload.data.EarlyVirtualizationPreloadResult
import com.eltavine.duckdetector.capability.earlypreload.data.EarlyVirtualizationPreloadSignal
import com.eltavine.duckdetector.capability.earlypreload.data.EarlyVirtualizationPreloadStore
import com.eltavine.duckdetector.capability.helperprocess.data.SacrificialSyscallPackResult
import com.eltavine.duckdetector.capability.helperprocess.data.VirtualizationIsolatedProbeManager
import com.eltavine.duckdetector.capability.helperprocess.data.VirtualizationNativeBridge
import com.eltavine.duckdetector.capability.helperprocess.data.VirtualizationNativeFinding
import com.eltavine.duckdetector.capability.helperprocess.data.VirtualizationProbeManager
import com.eltavine.duckdetector.capability.helperprocess.data.VirtualizationTrapResult
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.features.virtualization.data.probes.AsmCounterTrapProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.AsmRawSyscallTrapProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.DexPathProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.NativeSyscallParityTrapProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.NativeTimingTrapProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.UidIdentityProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationBuildProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationHostAppProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationHostAppProbeResult
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationPropertyProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationServiceProbe
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationImpact
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationReport
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignal
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalGroup
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationStage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class VirtualizationProcessInfo(
    val filesDir: String = "",
    val cacheDir: String = "",
    val codePath: String = "",
) {
    companion object {
        fun fromContext(context: Context?): VirtualizationProcessInfo {
            val appContext = context?.applicationContext ?: return VirtualizationProcessInfo()
            return VirtualizationProcessInfo(
                filesDir = runCatching { appContext.filesDir.absolutePath }.getOrDefault(""),
                cacheDir = runCatching { appContext.cacheDir.absolutePath }.getOrDefault(""),
                codePath = runCatching { appContext.applicationInfo.sourceDir }.getOrDefault(""),
            )
        }
    }
}

internal data class ConsistencyComputation(
    val crossProcessSignals: List<VirtualizationSignal> = emptyList(),
    val isolatedSignals: List<VirtualizationSignal> = emptyList(),
    val mountAnchorDriftCount: Int = 0,
) {
    val allSignals: List<VirtualizationSignal>
        get() = crossProcessSignals + isolatedSignals
}

class VirtualizationRepository(
    context: Context? = null,
    private val propertyProbe: VirtualizationPropertyProbe = VirtualizationPropertyProbe(),
    private val buildProbe: VirtualizationBuildProbe = VirtualizationBuildProbe(),
    private val serviceProbe: VirtualizationServiceProbe = VirtualizationServiceProbe(),
    private val dexPathProbe: DexPathProbe = DexPathProbe(context?.applicationContext),
    private val uidIdentityProbe: UidIdentityProbe = UidIdentityProbe(context?.applicationContext),
    private val nativeBridge: VirtualizationNativeBridge = VirtualizationNativeBridge(),
    private val hostAppProbe: VirtualizationHostAppProbe = VirtualizationHostAppProbe(
        context?.applicationContext,
    ),
    private val probeManager: VirtualizationProbeManager = VirtualizationProbeManager(
        context?.applicationContext,
    ),
    private val isolatedProbeManager: VirtualizationIsolatedProbeManager =
        VirtualizationIsolatedProbeManager(context?.applicationContext),
    private val nativeTimingTrapProbe: NativeTimingTrapProbe = NativeTimingTrapProbe(nativeBridge),
    private val nativeSyscallParityTrapProbe: NativeSyscallParityTrapProbe =
        NativeSyscallParityTrapProbe(nativeBridge),
    private val asmCounterTrapProbe: AsmCounterTrapProbe = AsmCounterTrapProbe(nativeBridge),
    private val asmRawSyscallTrapProbe: AsmRawSyscallTrapProbe =
        AsmRawSyscallTrapProbe(nativeBridge),
    private val preloadResultProvider: () -> EarlyVirtualizationPreloadResult = {
        EarlyVirtualizationPreloadStore.currentResult()
    },
    private val processInfoProvider: () -> VirtualizationProcessInfo = {
        VirtualizationProcessInfo.fromContext(context?.applicationContext)
    },
) : DetectorScanner<VirtualizationReport> {
    override suspend fun scan(): VirtualizationReport = withContext(Dispatchers.IO) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                VirtualizationReport.failed(throwable.message ?: "Virtualization scan failed.")
            }
    }

    internal suspend fun scanInternal(): VirtualizationReport {
        val propertySignals = propertyProbe.probe()
        val buildSignals = buildProbe.probe()
        val serviceResult = serviceProbe.probe()
        val dexPathResult = dexPathProbe.probe()
        val uidIdentityResult = uidIdentityProbe.probe()
        // Only this main-process snapshot feeds eglAvailable and the Graphics renderer method.
        val nativeSnapshot = nativeBridge.collectSnapshot(probeRenderer = true)
        val preloadResult = preloadResultProvider()
        val remoteSnapshot = probeManager.collect()
        val isolatedSnapshot = isolatedProbeManager.collect()
        val hostAppResult = hostAppProbe.probe()
        val mainProcessInfo = processInfoProvider()
        val nativeTimingTrap = nativeTimingTrapProbe.probe()
        val nativeSyscallParityTrap = nativeSyscallParityTrapProbe.probe()
        val asmCounterTrap = asmCounterTrapProbe.probe()
        val asmRawSyscallTrap = asmRawSyscallTrapProbe.probe()
        val syscallPackResult = probeManager.runSacrificialSyscallPack()

        val nativeSignals = nativeSnapshot.findings.map(::nativeFindingToSignal)
        val preloadSignals = buildPreloadSignals(preloadResult)
        val consistency = buildConsistencySignals(
            nativeSnapshot = nativeSnapshot,
            preloadResult = preloadResult,
            remoteSnapshot = remoteSnapshot,
            isolatedSnapshot = isolatedSnapshot,
            mainProcessInfo = mainProcessInfo,
            dexPathResult = dexPathResult,
            uidIdentityResult = uidIdentityResult,
        )
        val hostSignals = buildHostAppSignals(hostAppResult)
        val honeypotSignals = buildHoneypotSignals(
            nativeTimingTrap = nativeTimingTrap,
            nativeSyscallParityTrap = nativeSyscallParityTrap,
            asmCounterTrap = asmCounterTrap,
            asmRawSyscallTrap = asmRawSyscallTrap,
            syscallPackResult = syscallPackResult,
        )

        val signals = (
                propertySignals +
                        buildSignals +
                        serviceResult.signals +
                        dexPathResult.signals +
                        uidIdentityResult.signals +
                        nativeSignals +
                        preloadSignals +
                        consistency.allSignals +
                        hostSignals +
                        honeypotSignals
                )
            .distinctBy { it.id }
            .sortedWith(
                compareBy<VirtualizationSignal> { severityPriority(it.severity) }
                    .thenBy { groupPriority(it.group) }
                    .thenBy { it.label },
            )

        val runtimeSignals = signals.filter { it.group == VirtualizationSignalGroup.RUNTIME }
        val graphicsSignals = runtimeSignals.filter {
            it.label.contains("renderer", ignoreCase = true) ||
                    it.label.contains("graphics", ignoreCase = true)
        }
        val translationSignals =
            signals.filter { it.group == VirtualizationSignalGroup.TRANSLATION }

        return VirtualizationReport(
            stage = VirtualizationStage.READY,
            nativeAvailable = nativeSnapshot.available,
            startupPreloadAvailable = preloadResult.available,
            startupPreloadContextValid = preloadResult.isContextValid,
            crossProcessAvailable = remoteSnapshot.available,
            isolatedProcessAvailable = isolatedSnapshot.available,
            asmSupported = asmCounterTrap.supported || asmRawSyscallTrap.supported,
            eglAvailable = nativeSnapshot.eglAvailable,
            packageVisibility = hostAppResult.packageVisibility,
            dexPathEntryCount = dexPathResult.entryCount,
            dexPathHitCount = dexPathResult.hitCount,
            uidIdentityHitCount = uidIdentityResult.hitCount,
            environmentHitCount = countHits(signals, VirtualizationSignalGroup.ENVIRONMENT),
            translationHitCount = countHits(signals, VirtualizationSignalGroup.TRANSLATION),
            runtimeArtifactHitCount = countHits(signals, VirtualizationSignalGroup.RUNTIME),
            consistencyHitCount = countHits(signals, VirtualizationSignalGroup.CONSISTENCY),
            isolatedConsistencyHitCount = countHits(
                consistency.isolatedSignals,
                VirtualizationSignalGroup.CONSISTENCY,
            ),
            mountAnchorDriftCount = consistency.mountAnchorDriftCount,
            mountNamespaceAvailable = nativeSnapshot.mountNamespaceInode.isNotBlank(),
            honeypotHitCount = countHits(signals, VirtualizationSignalGroup.HONEYPOT),
            syscallPackSupported = syscallPackResult.supported,
            syscallPackHitCount = syscallPackResult.hitCount,
            hostAppCorroborationCount = signals.count { it.group == VirtualizationSignalGroup.HOST_APPS },
            mapLineCount = nativeSnapshot.mapLineCount,
            fdCount = nativeSnapshot.fdCount,
            mountInfoCount = nativeSnapshot.mountInfoCount,
            signals = signals,
            methods = buildMethods(
                propertySignals = propertySignals + buildSignals + serviceResult.signals,
                dexPathResult = dexPathResult,
                uidIdentityResult = uidIdentityResult,
                runtimeSignals = runtimeSignals.filterNot { it in graphicsSignals },
                graphicsSignals = graphicsSignals,
                translationSignals = translationSignals,
                preloadSignals = preloadSignals,
                preloadResult = preloadResult,
                crossProcessSignals = consistency.crossProcessSignals,
                isolatedSignals = consistency.isolatedSignals,
                remoteSnapshot = remoteSnapshot,
                isolatedSnapshot = isolatedSnapshot,
                hostAppResult = hostAppResult,
                nativeTimingTrap = nativeTimingTrap,
                nativeSyscallParityTrap = nativeSyscallParityTrap,
                asmCounterTrap = asmCounterTrap,
                asmRawSyscallTrap = asmRawSyscallTrap,
                syscallPackResult = syscallPackResult,
                listedServiceCount = serviceResult.listedServiceCount,
            ),
            impacts = buildImpacts(signals, hostAppResult),
        )
    }

    private fun countHits(
        signals: List<VirtualizationSignal>,
        group: VirtualizationSignalGroup
    ): Int {
        return signals.count {
            it.group == group &&
                    it.severity in setOf(
                VirtualizationSignalSeverity.WARNING,
                VirtualizationSignalSeverity.DANGER,
            )
        }
    }

    private fun nativeFindingToSignal(finding: VirtualizationNativeFinding): VirtualizationSignal {
        return VirtualizationSignal(
            id = "virt_native_${finding.group}_${finding.label}_${finding.value}",
            label = finding.label,
            value = finding.value,
            group = when (finding.group.uppercase()) {
                "ENVIRONMENT" -> VirtualizationSignalGroup.ENVIRONMENT
                "TRANSLATION" -> VirtualizationSignalGroup.TRANSLATION
                else -> VirtualizationSignalGroup.RUNTIME
            },
            severity = when (finding.severity.uppercase()) {
                "DANGER" -> VirtualizationSignalSeverity.DANGER
                "INFO" -> VirtualizationSignalSeverity.INFO
                "SAFE" -> VirtualizationSignalSeverity.SAFE
                else -> VirtualizationSignalSeverity.WARNING
            },
            detail = finding.detail,
            detailMonospace = finding.detail.shouldUseMonospace(),
        )
    }

    internal fun buildPreloadSignals(preloadResult: EarlyVirtualizationPreloadResult): List<VirtualizationSignal> {
        if (!preloadResult.hasRun) return emptyList()
        return preloadResult.activeSignals.map { signal ->
            VirtualizationSignal(
                id = "virt_preload_${signal.key.lowercase()}",
                label = "Startup preload ${signal.label}",
                value = if (signal.isDanger) "Detected" else "Review",
                group = if (signal == EarlyVirtualizationPreloadSignal.NATIVE_BRIDGE) {
                    VirtualizationSignalGroup.TRANSLATION
                } else {
                    VirtualizationSignalGroup.RUNTIME
                },
                severity = if (signal.isDanger) {
                    VirtualizationSignalSeverity.DANGER
                } else {
                    VirtualizationSignalSeverity.WARNING
                },
                detail = buildString {
                    append("Source=startup preload")
                    preloadResult.details.takeIf { it.isNotBlank() }?.let { detail ->
                        append(" | ")
                        append(detail)
                    }
                    preloadResult.mountNamespaceInode.takeIf { it.isNotBlank() }?.let {
                        append(" | mnt_ns=")
                        append(it)
                    }
                },
            )
        }
    }

    internal fun buildHostAppSignals(result: VirtualizationHostAppProbeResult): List<VirtualizationSignal> {
        return result.findings.map { finding ->
            VirtualizationSignal(
                id = "virt_host_${finding.target.packageName}",
                label = finding.target.appName,
                value = "Corroboration",
                group = VirtualizationSignalGroup.HOST_APPS,
                severity = VirtualizationSignalSeverity.INFO,
                detail = finding.methods.joinToString(separator = "\n") { method ->
                    method.detail?.let { "${method.kind.label}: $it" } ?: method.kind.label
                },
                detailMonospace = true,
            )
        }
    }

    internal fun buildHoneypotSignals(
        nativeTimingTrap: VirtualizationTrapResult,
        nativeSyscallParityTrap: VirtualizationTrapResult,
        asmCounterTrap: VirtualizationTrapResult,
        asmRawSyscallTrap: VirtualizationTrapResult,
        syscallPackResult: SacrificialSyscallPackResult,
    ): List<VirtualizationSignal> = buildList {
        addTrapSignal("Native timing trap", "virt_trap_native_timing", nativeTimingTrap)
        addTrapSignal(
            "Native syscall parity trap",
            "virt_trap_native_syscall_parity",
            nativeSyscallParityTrap,
        )
        addTrapSignal("ASM counter trap", "virt_trap_asm_counter", asmCounterTrap)
        addTrapSignal("ASM raw syscall trap", "virt_trap_asm_syscall", asmRawSyscallTrap)
        syscallPackResult.suspiciousItems.forEach { item ->
            add(
                VirtualizationSignal(
                    id = "virt_trap_pack_${item.label.lowercase().replace(' ', '_')}",
                    label = "Sacrificial ${item.label}",
                    value = "${item.suspiciousAttempts}/${item.completedAttempts}",
                    group = VirtualizationSignalGroup.HONEYPOT,
                    severity = VirtualizationSignalSeverity.WARNING,
                    detail = item.detail.ifBlank {
                        item.attempts.joinToString(separator = "\n") { attempt -> attempt.detail }
                    },
                    detailMonospace = true,
                ),
            )
        }
    }

    private fun MutableList<VirtualizationSignal>.addTrapSignal(
        label: String,
        id: String,
        result: VirtualizationTrapResult,
    ) {
        if (!result.suspicious) return
        add(
            VirtualizationSignal(
                id = id,
                label = label,
                value = "${result.suspiciousAttempts}/${result.completedAttempts}",
                group = VirtualizationSignalGroup.HONEYPOT,
                severity = VirtualizationSignalSeverity.WARNING,
                detail = result.detail,
                detailMonospace = true,
            ),
        )
    }

    internal fun buildImpacts(
        signals: List<VirtualizationSignal>,
        hostAppResult: VirtualizationHostAppProbeResult,
    ): List<VirtualizationImpact> {
        if (signals.isEmpty()) {
            return listOf(
                VirtualizationImpact(
                    text = "No direct emulator, AVF guest, translation, classpath, or consistency drift signal surfaced from the current app context.",
                    severity = VirtualizationSignalSeverity.SAFE,
                ),
            )
        }
        if (
            signals.none {
                it.severity == VirtualizationSignalSeverity.DANGER ||
                        it.severity == VirtualizationSignalSeverity.WARNING
            } &&
            hostAppResult.findings.isNotEmpty()
        ) {
            return listOf(
                VirtualizationImpact(
                    text = "Known virtualization host apps are installed, but current process probes did not confirm guest or translated execution.",
                    severity = VirtualizationSignalSeverity.INFO,
                ),
            )
        }
        return signals.take(5).map { signal ->
            VirtualizationImpact(
                text = buildString {
                    append(signal.label)
                    signal.detail?.takeIf { it.isNotBlank() }?.let { detail ->
                        append(": ")
                        append(detail.lineSequence().firstOrNull().orEmpty())
                    }
                },
                severity = signal.severity,
            )
        }
    }

    private fun severityPriority(severity: VirtualizationSignalSeverity): Int {
        return when (severity) {
            VirtualizationSignalSeverity.DANGER -> 0
            VirtualizationSignalSeverity.WARNING -> 1
            VirtualizationSignalSeverity.INFO -> 2
            VirtualizationSignalSeverity.SAFE -> 3
        }
    }

    private fun groupPriority(group: VirtualizationSignalGroup): Int {
        return when (group) {
            VirtualizationSignalGroup.ENVIRONMENT -> 0
            VirtualizationSignalGroup.TRANSLATION -> 1
            VirtualizationSignalGroup.RUNTIME -> 2
            VirtualizationSignalGroup.CONSISTENCY -> 3
            VirtualizationSignalGroup.HONEYPOT -> 4
            VirtualizationSignalGroup.HOST_APPS -> 5
        }
    }

    private fun String?.shouldUseMonospace(): Boolean {
        val value = this.orEmpty()
        return value.contains("/proc/") ||
                value.contains("/data/") ||
                value.contains("/dev/") ||
                value.contains(".so") ||
                value.contains("=") ||
                value.contains(":") ||
                value.contains("|")
    }
}
