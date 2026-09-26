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

package com.eltavine.duckdetector.features.nativeroot.presentation

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethod
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodOutcome
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodResult
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootStage
import com.eltavine.duckdetector.features.nativeroot.presentation.model.NativeRootHeaderFact
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeRootCardModelMapperTest {

    private val mapper = NativeRootCardModelMapper()

    @Test
    fun `cgroup leakage contributes method and scan rows`() {
        val report = NativeRootReport(
            stage = NativeRootStage.READY,
            findings = listOf(
                NativeRootFinding(
                    id = "cgroup_visibility_4242",
                    label = "Selective cgroup visibility",
                    value = "PID 4242",
                    detail = "Java File view missed a PID that native getdents exposed.",
                    group = NativeRootGroup.PROCESS,
                    severity = NativeRootFindingSeverity.DANGER,
                ),
            ),
            rootDetected = false,
            kernelSuDetected = false,
            aPatchDetected = false,
            magiskDetected = false,
            susfsDetected = false,
            kernelSuVersion = 0L,
            nativeAvailable = true,
            prctlProbeHit = false,
            susfsProbeHit = false,
            pathHitCount = 0,
            pathCheckCount = 12,
            processHitCount = 0,
            processCheckedCount = 4,
            processDeniedCount = 1,
            cgroupAvailable = true,
            cgroupPathCheckCount = 32,
            cgroupAccessiblePathCount = 2,
            cgroupProcessCheckedCount = 3,
            cgroupProcDeniedCount = 1,
            cgroupHitCount = 1,
            kernelHitCount = 0,
            kernelSourceCount = 3,
            propertyHitCount = 0,
            propertyCheckCount = 5,
            methods = listOf(
                NativeRootMethodResult(
                    method = NativeRootMethod.CGROUP_LEAKAGE,
                    summary = "1 hit(s)",
                    outcome = NativeRootMethodOutcome.DETECTED,
                    detail = "Enumerate per-UID cgroup trees and compare native vs Java visibility.",
                ),
            ),
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.DANGER, model.status.severity)
        assertTrue(model.subtitle.contains("cgroup", ignoreCase = true))
        assertTrue(model.methodRows.any { it.label == "cgroupLeakage" && it.value == "1 hit(s)" })
        assertEquals("32", model.scanRows.single { it.label == "Cgroup paths" }.value)
        assertEquals("1", model.scanRows.single { it.label == "Cgroup hits" }.value)
        assertTrue(model.runtimeRows.any { it.label == "Selective cgroup visibility" })
    }

    @Test
    fun `blocked ksu supercall is shown as support not clean`() {
        val report = NativeRootReport(
            stage = NativeRootStage.READY,
            findings = emptyList(),
            rootDetected = false,
            kernelSuDetected = false,
            aPatchDetected = false,
            magiskDetected = false,
            susfsDetected = false,
            kernelSuVersion = 0L,
            nativeAvailable = true,
            prctlProbeHit = false,
            susfsProbeHit = false,
            pathHitCount = 0,
            pathCheckCount = 12,
            processHitCount = 0,
            processCheckedCount = 4,
            processDeniedCount = 0,
            cgroupAvailable = false,
            cgroupPathCheckCount = 0,
            cgroupAccessiblePathCount = 0,
            cgroupProcessCheckedCount = 0,
            cgroupProcDeniedCount = 0,
            cgroupHitCount = 0,
            kernelHitCount = 0,
            kernelSourceCount = 3,
            propertyHitCount = 0,
            propertyCheckCount = 5,
            methods = listOf(
                NativeRootMethodResult(
                    method = NativeRootMethod.KSU_READONLY_SUPERCALL,
                    summary = "Blocked",
                    outcome = NativeRootMethodOutcome.SUPPORT,
                    detail = "reboot() helper was blocked by seccomp.",
                ),
            ),
            ksuSupercallAttempted = true,
            ksuSupercallBlocked = true,
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertTrue(model.summary.contains("blocked by app seccomp"))
        assertEquals("Limited", model.headerFacts.single { it.fact == NativeRootHeaderFact.DIRECT }.value)
        assertTrue(
            model.nativeRows.any {
                it.label == "KSU supercall" && it.value == "Blocked by seccomp"
            }
        )
        assertTrue(model.methodRows.any { it.label == "ksuReadonlySupercall" && it.value == "Blocked" })
    }

    @Test
    fun `throne hunt failure exposes stage counters and hidden diagnostics`() {
        val report = NativeRootReport.loading().copy(
            stage = NativeRootStage.READY,
            methods = listOf(
                NativeRootMethodResult(
                    method = NativeRootMethod.KSU_THRONE_HUNT,
                    summary = "STIMULUS_FAILED",
                    outcome = NativeRootMethodOutcome.SUPPORT,
                    detail = "PM binder diagnostic",
                ),
            ),
            ksuThroneHuntAvailable = false,
            ksuThroneHuntWatchDenied = false,
            ksuThroneHuntPackageDirectory = "/data/app/package",
            ksuThroneHuntOpenCount = 0,
            ksuThroneHuntAccessCount = 0,
            ksuThroneHuntStimulusApplied = false,
            ksuThroneHuntCollectionOutcome = "COLLECTED",
            ksuThroneHuntCollectionDetail = "",
            ksuThroneHuntFailureStage = "STIMULUS_FAILED",
            ksuThroneHuntBaselineHitCount = 2,
            ksuThroneHuntRawEventCount = 5,
            ksuThroneHuntInvalidEventCount = 1,
            ksuThroneHuntWatchDescriptor = 12,
            ksuThroneHuntStimulusDetail = "setMimeGroup failed: binder unavailable",
            ksuThroneHuntDiagnosticDetail = "round detail",
        )

        val model = mapper.map(report)
        val throneRow = model.scanRows.single { it.label == "Throne hunt" }
        val counterRow = model.scanRows.single { it.label == "Throne hunt counters" }
        val methodRow = model.methodRows.single { it.label == "ksuThroneHunt" }

        assertEquals("STIMULUS_FAILED", throneRow.value)
        assertTrue(counterRow.value.contains("raw=5"))
        assertTrue(counterRow.value.contains("invalid=1"))
        assertTrue(counterRow.value.contains("baseline=2"))
        assertTrue(methodRow.hiddenCopyText!!.contains("failureStage=STIMULUS_FAILED"))
        assertTrue(methodRow.hiddenCopyText.contains("setMimeGroup failed: binder unavailable"))
        assertTrue(methodRow.hiddenCopyText.contains("watchDescriptor=12"))
        assertTrue(methodRow.hiddenCopyText.contains("--- detail ---"))
        assertTrue(methodRow.hiddenCopyText.contains("round detail"))
    }

    @Test
    fun `mount drift and manager fingerprint land in runtime method and scan rows`() {
        val report = NativeRootReport(
            stage = NativeRootStage.READY,
            findings = listOf(
                NativeRootFinding(
                    id = "mount_anchor_drift_isolated",
                    label = "Isolated mount anchor drift",
                    value = "1 anchor(s)",
                    detail = "/system main=dev=8:1 root=/ point=/system fs=ext4 source=/dev/block/dm-1 isolated=dev=0:22 root=/ point=/system fs=overlay source=overlay",
                    group = NativeRootGroup.PROCESS,
                    severity = NativeRootFindingSeverity.WARNING,
                    detailMonospace = true,
                ),
                NativeRootFinding(
                    id = "ksu_manager_manifest",
                    label = "KernelSU manager manifest",
                    value = "3/3 traits",
                    detail = "package=me.weishu.kernelsu",
                    group = NativeRootGroup.PACKAGE,
                    severity = NativeRootFindingSeverity.WARNING,
                    detailMonospace = true,
                ),
            ),
            rootDetected = false,
            kernelSuDetected = false,
            aPatchDetected = false,
            magiskDetected = false,
            susfsDetected = false,
            kernelSuVersion = 0L,
            nativeAvailable = true,
            prctlProbeHit = false,
            susfsProbeHit = false,
            pathHitCount = 0,
            pathCheckCount = 12,
            processHitCount = 0,
            processCheckedCount = 4,
            processDeniedCount = 0,
            cgroupAvailable = true,
            cgroupPathCheckCount = 32,
            cgroupAccessiblePathCount = 2,
            cgroupProcessCheckedCount = 3,
            cgroupProcDeniedCount = 0,
            cgroupHitCount = 0,
            kernelHitCount = 0,
            kernelSourceCount = 3,
            propertyHitCount = 0,
            propertyCheckCount = 5,
            methods = listOf(
                NativeRootMethodResult(
                    method = NativeRootMethod.ISOLATED_MOUNT_DRIFT,
                    summary = "1 anchor(s)",
                    outcome = NativeRootMethodOutcome.WARNING,
                    detail = "Compared mount anchors.",
                ),
                NativeRootMethodResult(
                    method = NativeRootMethod.KSU_MANAGER_FINGERPRINT,
                    summary = "3/3 traits",
                    outcome = NativeRootMethodOutcome.WARNING,
                    detail = "Manager manifest fingerprint.",
                ),
            ),
            isolatedMountProbeAvailable = true,
            mainMountNamespaceInode = "mnt:[41]",
            isolatedMountNamespaceInode = "mnt:[42]",
            mountDriftSignalCount = 1,
            mountAnchorDriftCount = 1,
            ksuManagerPackagePresent = true,
            ksuManagerTraitHitCount = 3,
        )

        val model = mapper.map(report)

        assertTrue(model.runtimeRows.any { it.label == "Isolated mount anchor drift" })
        assertTrue(model.runtimeRows.any { it.label == "KernelSU manager manifest" })
        assertTrue(model.methodRows.any { it.label == "isolatedMountDrift" && it.value == "1 anchor(s)" })
        assertTrue(model.methodRows.any { it.label == "ksuManagerFingerprint" && it.value == "3/3 traits" })
        assertEquals("mnt:[41]", model.scanRows.single { it.label == "Main mnt ns" }.value)
        assertEquals("mnt:[42]", model.scanRows.single { it.label == "Isolated mnt ns" }.value)
        assertEquals("1", model.scanRows.single { it.label == "Mount drift hits" }.value)
        assertEquals("Present", model.scanRows.single { it.label == "Manager package" }.value)
        assertEquals("3/3", model.scanRows.single { it.label == "Manager traits" }.value)
    }
}
