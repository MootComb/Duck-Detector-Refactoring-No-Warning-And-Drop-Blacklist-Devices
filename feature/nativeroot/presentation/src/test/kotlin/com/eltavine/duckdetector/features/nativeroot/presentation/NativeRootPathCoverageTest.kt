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
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootStage
import org.junit.Assert.assertEquals
import org.junit.Test

class NativeRootPathCoverageTest {

    private val mapper = NativeRootCardModelMapper()

    private fun report(pathDeniedCount: Int) = NativeRootReport(
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
        pathCheckCount = 25,
        pathDeniedCount = pathDeniedCount,
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
        methods = emptyList(),
        ksuSupercallAttempted = true,
        isolatedMountProbeAvailable = true,
        ksuThroneHuntAvailable = true,
        ksuThroneHuntStimulusApplied = true,
    )

    @Test
    fun `fully observable paths stay all clear`() {
        val model = mapper.map(report(pathDeniedCount = 0))

        assertEquals(DetectionSeverity.ALL_CLEAR, model.status.severity)
        assertEquals("25", model.scanRows.single { it.label == "Paths checked" }.value)
    }

    @Test
    fun `paths under a directory this app may not search reduce coverage`() {
        val model = mapper.map(report(pathDeniedCount = 11))

        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertEquals("25 · 11 not observable", model.scanRows.single { it.label == "Paths checked" }.value)
    }
}
