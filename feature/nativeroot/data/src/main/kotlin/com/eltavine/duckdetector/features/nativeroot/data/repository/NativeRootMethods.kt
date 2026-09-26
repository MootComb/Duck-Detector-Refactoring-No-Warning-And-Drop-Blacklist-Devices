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

package com.eltavine.duckdetector.features.nativeroot.data.repository

import com.eltavine.duckdetector.features.nativeroot.data.native.NativeRootNativeSnapshot
import com.eltavine.duckdetector.features.nativeroot.data.probes.CgroupProcessLeakProbeResult
import com.eltavine.duckdetector.features.nativeroot.data.probes.KernelSuManagerFingerprintProbeResult
import com.eltavine.duckdetector.features.nativeroot.data.probes.KernelSuThroneHuntProbeResult
import com.eltavine.duckdetector.features.nativeroot.data.probes.MountNamespaceDriftProbeResult
import com.eltavine.duckdetector.features.nativeroot.data.probes.TempRootArtifactProbeResult
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodResult

internal fun buildMethods(
    snapshot: NativeRootNativeSnapshot,
    findings: List<NativeRootFinding>,
    shellTmpDetail: String,
    rootProcessDetail: String,
    cgroupResult: CgroupProcessLeakProbeResult,
    mountNamespaceResult: MountNamespaceDriftProbeResult,
    managerFingerprintResult: KernelSuManagerFingerprintProbeResult,
    tempRootArtifactResult: TempRootArtifactProbeResult,
    throneHuntResult: KernelSuThroneHuntProbeResult,
): List<NativeRootMethodResult> {
    val directFindings =
        findings.filter { it.group == NativeRootGroup.SYSCALL || it.group == NativeRootGroup.SIDE_CHANNEL }
    val runtimeFindings =
        findings.filter {
            it.group == NativeRootGroup.PATH ||
                    it.group == NativeRootGroup.PROCESS ||
                    it.group == NativeRootGroup.PACKAGE
        }
    val kernelFindings = findings.filter { it.group == NativeRootGroup.KERNEL }
    val propertyFindings = findings.filter { it.group == NativeRootGroup.PROPERTY }

    val evidence = NativeRootMethodEvidence(
        snapshot,
        findings,
        shellTmpDetail,
        rootProcessDetail,
        cgroupResult,
        mountNamespaceResult,
        managerFingerprintResult,
        tempRootArtifactResult,
        throneHuntResult,
        directFindings,
        runtimeFindings,
        kernelFindings,
        propertyFindings,
    )
    return evidence.kernelInterfaceMethods() + evidence.namespaceAndArtifactMethods()
}

/** What every Native Root method row reads: the scan's evidence and its findings by group. */
internal class NativeRootMethodEvidence(
    val snapshot: NativeRootNativeSnapshot,
    val findings: List<NativeRootFinding>,
    val shellTmpDetail: String,
    val rootProcessDetail: String,
    val cgroupResult: CgroupProcessLeakProbeResult,
    val mountNamespaceResult: MountNamespaceDriftProbeResult,
    val managerFingerprintResult: KernelSuManagerFingerprintProbeResult,
    val tempRootArtifactResult: TempRootArtifactProbeResult,
    val throneHuntResult: KernelSuThroneHuntProbeResult,
    val directFindings: List<NativeRootFinding>,
    val runtimeFindings: List<NativeRootFinding>,
    val kernelFindings: List<NativeRootFinding>,
    val propertyFindings: List<NativeRootFinding>,
)
