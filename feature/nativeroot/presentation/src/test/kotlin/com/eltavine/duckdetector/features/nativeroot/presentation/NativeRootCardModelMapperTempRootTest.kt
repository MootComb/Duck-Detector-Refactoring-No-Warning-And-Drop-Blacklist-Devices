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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeRootCardModelMapperTempRootTest {

    private val mapper = NativeRootCardModelMapper()

    @Test
    fun `warning path hits stay warning in scan rows`() {
        val report = NativeRootReport(
            stage = NativeRootStage.READY,
            findings = listOf(
                NativeRootFinding(
                    id = "path_resetprop_tmp",
                    label = "resetprop tmp residue",
                    value = "Present",
                    detail = "Category: Shell tmp artifact\nConfirmations: 2/3\nEvidence: stat, openat\n/data/local/tmp/resetprop",
                    group = NativeRootGroup.PATH,
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
            pathHitCount = 1,
            pathCheckCount = 36,
            processHitCount = 0,
            processCheckedCount = 4,
            processDeniedCount = 0,
            cgroupAvailable = true,
            cgroupPathCheckCount = 32,
            cgroupAccessiblePathCount = 0,
            cgroupProcessCheckedCount = 0,
            cgroupProcDeniedCount = 0,
            cgroupHitCount = 0,
            kernelHitCount = 0,
            kernelSourceCount = 3,
            propertyHitCount = 0,
            propertyCheckCount = 5,
            methods = emptyList(),
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.WARNING, model.status.severity)
        assertEquals(DetectionSeverity.WARNING, model.scanRows.single { it.label == "Path hits" }.status.severity)
        assertTrue(model.runtimeRows.any { it.label == "resetprop tmp residue" })
    }

    @Test
    fun `temp root CVE exploit detection produces danger verdict`() {
        val report = NativeRootReport(
            stage = NativeRootStage.READY,
            findings = listOf(
                NativeRootFinding(
                    id = "temp_root_cve_0",
                    label = "Temp root CVE exploit artifact",
                    value = "libCVE43499root.so",
                    detail = "File \"libCVE43499root.so\" in /data/local/tmp matches CVE-2026-43499 temp root exploit pattern.",
                    group = NativeRootGroup.PATH,
                    severity = NativeRootFindingSeverity.DANGER,
                    detailMonospace = true,
                ),
                NativeRootFinding(
                    id = "temp_root_artifact_1",
                    label = "Temp root artifact",
                    value = "ksud-aarch64-linux-android",
                    detail = "File \"ksud-aarch64-linux-android\" in /data/local/tmp is a known temporary root infrastructure artifact.",
                    group = NativeRootGroup.PATH,
                    severity = NativeRootFindingSeverity.DANGER,
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
            pathHitCount = 2,
            pathCheckCount = 36,
            processHitCount = 0,
            processCheckedCount = 4,
            processDeniedCount = 0,
            cgroupAvailable = true,
            cgroupPathCheckCount = 32,
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
                    method = NativeRootMethod.TEMP_ROOT_ARTIFACTS,
                    summary = "CVE-2026-43499",
                    outcome = NativeRootMethodOutcome.DETECTED,
                    detail = "Scans /data/local/tmp for temp root exploit artifacts.",
                ),
            ),
            tempRootDetected = true,
            tempRootCveExploitDetected = true,
            tempRootArtifactHitCount = 2,
            tempRootArtifactCheckCount = 8,
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.DANGER, model.status.severity)
        assertTrue(model.verdict.contains("CVE-2026-43499"))
        assertTrue(model.runtimeRows.any { it.label == "Temp root CVE exploit artifact" })
        assertTrue(model.runtimeRows.any { it.label == "Temp root artifact" })
        assertEquals("2", model.scanRows.single { it.label == "Temp root hits" }.value)
        assertEquals(DetectionSeverity.DANGER, model.scanRows.single { it.label == "Temp root hits" }.status.severity)
        assertTrue(model.methodRows.any { it.label == "tempRootArtifacts" && it.value == "CVE-2026-43499" })
    }

    @Test
    fun `temp root detection without CVE produces danger verdict`() {
        val report = NativeRootReport(
            stage = NativeRootStage.READY,
            findings = listOf(
                NativeRootFinding(
                    id = "temp_root_artifact_0",
                    label = "Temp root artifact",
                    value = "ksu-helper",
                    detail = "File \"ksu-helper\" in /data/local/tmp is a known temporary root infrastructure artifact.",
                    group = NativeRootGroup.PATH,
                    severity = NativeRootFindingSeverity.DANGER,
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
            pathHitCount = 1,
            pathCheckCount = 36,
            processHitCount = 0,
            processCheckedCount = 4,
            processDeniedCount = 0,
            cgroupAvailable = true,
            cgroupPathCheckCount = 32,
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
                    method = NativeRootMethod.TEMP_ROOT_ARTIFACTS,
                    summary = "1 hit(s)",
                    outcome = NativeRootMethodOutcome.DETECTED,
                    detail = "Scans /data/local/tmp for temp root exploit artifacts.",
                ),
            ),
            tempRootDetected = true,
            tempRootCveExploitDetected = false,
            tempRootArtifactHitCount = 1,
            tempRootArtifactCheckCount = 8,
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.DANGER, model.status.severity)
        assertTrue(model.verdict.contains("Temp root"))
        assertTrue(model.runtimeRows.any { it.label == "Temp root artifact" })
    }
}
