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
import com.eltavine.duckdetector.capability.helperprocess.data.VirtualizationNativeFinding
import com.eltavine.duckdetector.capability.helperprocess.data.VirtualizationNativeSnapshot
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationHostAppFinding
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationHostAppProbeResult
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationHostDetectionMethod
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationHostDetectionMethodKind
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationServiceProbeResult
import com.eltavine.duckdetector.features.virtualization.data.rules.VirtualizationHostAppTarget
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationMethodOutcome
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalGroup
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VirtualizationRepositoryTest {

    @Test
    fun `classic emulator strong props and runtime hits map to danger`() = runBlocking {
        val report = repository(
            propertySignals = listOf(
                signal(
                    "prop",
                    "ro.kernel.qemu",
                    VirtualizationSignalGroup.ENVIRONMENT,
                    VirtualizationSignalSeverity.DANGER
                ),
            ),
            nativeSnapshot = VirtualizationNativeSnapshot(
                available = true,
                findings = listOf(
                    VirtualizationNativeFinding(
                        "RUNTIME",
                        "DANGER",
                        "Emulator device node",
                        "/dev/qemu_pipe",
                        "/dev/qemu_pipe"
                    ),
                ),
            ),
        ).scanInternal()

        assertTrue(report.dangerSignals.isNotEmpty())
        assertEquals(1, report.environmentHitCount)
        assertTrue(report.runtimeArtifactHitCount > 0)
    }

    @Test
    fun `translation only maps to warning`() = runBlocking {
        val report = repository(
            propertySignals = listOf(
                signal(
                    "bridge",
                    "ro.dalvik.vm.native.bridge",
                    VirtualizationSignalGroup.TRANSLATION,
                    VirtualizationSignalSeverity.WARNING
                ),
            ),
        ).scanInternal()

        assertTrue(report.dangerSignals.isEmpty())
        assertEquals(1, report.warningSignals.size)
        assertEquals(1, report.translationHitCount)
    }

    @Test
    fun `host apps only remain corroboration only`() = runBlocking {
        val report = repository(
            hostAppResult = VirtualizationHostAppProbeResult(
                packageVisibility = InstalledPackageVisibility.FULL,
                findings = listOf(
                    VirtualizationHostAppFinding(
                        target = VirtualizationHostAppTarget("com.vmos.pro", "VMOS Pro"),
                        methods = listOf(
                            VirtualizationHostDetectionMethod(
                                VirtualizationHostDetectionMethodKind.PACKAGE_MANAGER,
                            ),
                        ),
                    ),
                ),
            ),
        ).scanInternal()

        assertTrue(report.dangerSignals.isEmpty())
        assertTrue(report.warningSignals.isEmpty())
        assertTrue(report.onlyHostAppCorroboration)
        assertEquals(1, report.hostAppCorroborationCount)
        assertEquals(
            VirtualizationMethodOutcome.INFO,
            report.methods.first { it.label == "Host apps" }.outcome,
        )
    }

    @Test
    fun `failed ServiceManager lookups leave the properties row partial`() = runBlocking {
        val report = repository(
            serviceResult = VirtualizationServiceProbeResult(0, emptyList(), failure = "SecurityException"),
        ).scanInternal()

        val row = report.methods.first { it.label == "Properties and build" }
        assertEquals("Partial", row.summary)
        assertEquals(VirtualizationMethodOutcome.SUPPORT, row.outcome)
        assertTrue(row.detail.orEmpty().contains("SecurityException"))
    }

    @Test
    fun `answered ServiceManager lookups keep the properties row clean`() = runBlocking {
        val row = repository().scanInternal().methods.first { it.label == "Properties and build" }

        assertEquals(VirtualizationMethodOutcome.CLEAN, row.outcome)
        assertTrue(row.detail.orEmpty().contains("Listed services: 0"))
    }

    @Test
    fun `capability only signal does not count as detection`() = runBlocking {
        val report = repository(
            propertySignals = listOf(
                signal(
                    "cap",
                    "Hypervisor capability",
                    VirtualizationSignalGroup.ENVIRONMENT,
                    VirtualizationSignalSeverity.INFO
                ),
            ),
        ).scanInternal()

        assertTrue(report.dangerSignals.isEmpty())
        assertTrue(report.warningSignals.isEmpty())
        assertFalse(report.onlyHostAppCorroboration)
    }

    @Test
    fun `preload only strong evidence enters report`() = runBlocking {
        val report = repository(
            preloadResult = EarlyVirtualizationPreloadResult(
                hasRun = true,
                detected = true,
                qemuPropertyDetected = true,
                details = "preload",
            ).normalize(),
        ).scanInternal()

        assertTrue(report.startupPreloadAvailable)
        assertTrue(report.dangerSignals.any { it.id.contains("preload") })
    }

    @Test
    fun `syscall pack suspicious item adds honeypot warning`() = runBlocking {
        val report = repository(
            syscallPackResult = SacrificialSyscallPackResult(
                available = true,
                supported = true,
                items = listOf(
                    com.eltavine.duckdetector.capability.helperprocess.data.VirtualizationSyscallPackItem(
                        label = "openat2",
                        supported = true,
                        completedAttempts = 3,
                        suspiciousAttempts = 2,
                        detail = "libc/raw/asm mismatch",
                    ),
                ),
            ),
        ).scanInternal()

        assertEquals(1, report.syscallPackHitCount)
        assertTrue(report.honeypotRows.any { it.label == "Sacrificial openat2" })
        assertEquals(
            VirtualizationMethodOutcome.WARNING,
            report.methods.first { it.label == "Sacrificial syscall pack" }.outcome,
        )
    }

    @Test
    fun `unsupported syscall pack stays support`() = runBlocking {
        val report = repository(
            syscallPackResult = SacrificialSyscallPackResult(
                available = true,
                supported = false,
                detail = "SIGSYS disabled the pack",
            ),
        ).scanInternal()

        assertEquals(0, report.syscallPackHitCount)
        assertEquals(
            VirtualizationMethodOutcome.SUPPORT,
            report.methods.first { it.label == "Sacrificial syscall pack" }.outcome,
        )
    }

    @Test
    fun `main process scan requests renderer evidence`() = runBlocking {
        // Helpers pass probeRenderer = false (#141), so eglAvailable has to come from this call.
        val rendererRequests = mutableListOf<Boolean>()

        repository(rendererRequests = rendererRequests).scanInternal()

        assertEquals(listOf(true), rendererRequests)
    }

}
