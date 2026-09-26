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
import com.eltavine.duckdetector.capability.helperprocess.data.HelperProbeManager
import com.eltavine.duckdetector.capability.helperprocess.data.HelperProcessProfile
import com.eltavine.duckdetector.capability.helperprocess.data.HelperProcessSnapshot
import com.eltavine.duckdetector.capability.helperprocess.data.IsolatedHelperProbeManager
import com.eltavine.duckdetector.capability.helperprocess.data.SacrificialSyscallPackResult
import com.eltavine.duckdetector.capability.helperprocess.data.VirtualizationNativeBridge
import com.eltavine.duckdetector.capability.helperprocess.data.VirtualizationNativeSnapshot
import com.eltavine.duckdetector.capability.helperprocess.data.VirtualizationTrapResult
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import com.eltavine.duckdetector.features.virtualization.data.probes.AsmCounterTrapProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.AsmRawSyscallTrapProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.DexPathProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.DexPathProbeResult
import com.eltavine.duckdetector.features.virtualization.data.probes.NativeSyscallParityTrapProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.NativeTimingTrapProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.UidIdentityProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.UidIdentityProbeResult
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationBuildProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationHostAppProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationHostAppProbeResult
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationPropertyProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationServiceProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationServiceProbeResult
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignal
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalGroup
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity

internal fun repository(
    propertySignals: List<VirtualizationSignal> = emptyList(),
    buildSignals: List<VirtualizationSignal> = emptyList(),
    serviceResult: VirtualizationServiceProbeResult = VirtualizationServiceProbeResult(
        0,
        emptyList()
    ),
    dexPathResult: DexPathProbeResult = DexPathProbeResult(),
    uidIdentityResult: UidIdentityProbeResult = UidIdentityProbeResult(),
    nativeSnapshot: VirtualizationNativeSnapshot = VirtualizationNativeSnapshot(available = true),
    preloadResult: EarlyVirtualizationPreloadResult = EarlyVirtualizationPreloadResult.empty(),
    remoteSnapshot: HelperProcessSnapshot = HelperProcessSnapshot(),
    isolatedSnapshot: HelperProcessSnapshot = HelperProcessSnapshot(
        profile = HelperProcessProfile.ISOLATED,
    ),
    hostAppResult: VirtualizationHostAppProbeResult = VirtualizationHostAppProbeResult(
        packageVisibility = InstalledPackageVisibility.FULL,
        findings = emptyList(),
    ),
    processInfo: VirtualizationProcessInfo = VirtualizationProcessInfo(),
    syscallPackResult: SacrificialSyscallPackResult = SacrificialSyscallPackResult(),
    rendererRequests: MutableList<Boolean> = mutableListOf(),
): VirtualizationRepository {
    return VirtualizationRepository(
        propertyProbe = object : VirtualizationPropertyProbe() {
            override fun probe(): List<VirtualizationSignal> = propertySignals
        },
        buildProbe = object : VirtualizationBuildProbe() {
            override fun probe(): List<VirtualizationSignal> = buildSignals
        },
        serviceProbe = object : VirtualizationServiceProbe() {
            override fun probe(): VirtualizationServiceProbeResult = serviceResult
        },
        dexPathProbe = object : DexPathProbe() {
            override fun probe(): DexPathProbeResult = dexPathResult
        },
        uidIdentityProbe = object : UidIdentityProbe() {
            override fun probe(): UidIdentityProbeResult = uidIdentityResult
        },
        nativeBridge = object : VirtualizationNativeBridge() {
            override fun collectSnapshot(probeRenderer: Boolean): VirtualizationNativeSnapshot {
                rendererRequests += probeRenderer
                return nativeSnapshot
            }
        },
        hostAppProbe = object : VirtualizationHostAppProbe() {
            override fun probe(): VirtualizationHostAppProbeResult = hostAppResult
        },
        probeManager = object : HelperProbeManager() {
            override suspend fun collect(): HelperProcessSnapshot = remoteSnapshot
            override suspend fun runSacrificialSyscallPack(): SacrificialSyscallPackResult =
                syscallPackResult
        },
        isolatedProbeManager = object : IsolatedHelperProbeManager() {
            override suspend fun collect(): HelperProcessSnapshot = isolatedSnapshot
        },
        nativeTimingTrapProbe = object : NativeTimingTrapProbe() {
            override fun probe(): VirtualizationTrapResult = VirtualizationTrapResult()
        },
        nativeSyscallParityTrapProbe = object : NativeSyscallParityTrapProbe() {
            override fun probe(): VirtualizationTrapResult = VirtualizationTrapResult()
        },
        asmCounterTrapProbe = object : AsmCounterTrapProbe() {
            override fun probe(): VirtualizationTrapResult = VirtualizationTrapResult()
        },
        asmRawSyscallTrapProbe = object : AsmRawSyscallTrapProbe() {
            override fun probe(): VirtualizationTrapResult = VirtualizationTrapResult()
        },
        preloadResultProvider = { preloadResult },
        processInfoProvider = { processInfo },
    )
}

internal fun signal(
    id: String,
    label: String,
    group: VirtualizationSignalGroup,
    severity: VirtualizationSignalSeverity,
): VirtualizationSignal {
    return VirtualizationSignal(
        id = id,
        label = label,
        value = label,
        group = group,
        severity = severity,
        detail = label,
    )
}
