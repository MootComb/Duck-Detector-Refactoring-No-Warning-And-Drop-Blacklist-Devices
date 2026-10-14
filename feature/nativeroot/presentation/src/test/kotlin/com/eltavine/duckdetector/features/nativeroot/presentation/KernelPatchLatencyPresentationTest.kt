/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.core.report.ReportBlock
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
import org.junit.Test

class KernelPatchLatencyPresentationTest {
    @Test
    fun `a timing-only warning stays unattributed in the card and SDK export`() {
        val detail = "Key path: 4.2810 us, empty key: 0.4600 us, ratio: 9.31. " +
            "Supporting timing evidence only; this ratio neither identifies nor excludes KernelPatch."
        val finding = NativeRootFinding(
            id = "native_latency",
            label = "Supercall key-length timing ratio",
            value = "Elevated ratio (supporting evidence)",
            detail = detail,
            group = NativeRootGroup.SIDE_CHANNEL,
            severity = NativeRootFindingSeverity.WARNING,
        )
        val report = NativeRootReport.loading().copy(
            stage = NativeRootStage.READY,
            nativeAvailable = true,
            ksuSupercallAttempted = true,
            cgroupAvailable = true,
            isolatedMountProbeAvailable = true,
            ksuThroneHuntAvailable = true,
            ksuThroneHuntStimulusApplied = true,
            kernelPatchSideChannel = true,
            findings = listOf(finding),
            methods = listOf(
                NativeRootMethodResult(
                    method = NativeRootMethod.NR_SUPERCALL_PROBE,
                    summary = "Elevated ratio",
                    outcome = NativeRootMethodOutcome.SUPPORT,
                    detail = detail,
                ),
            ),
        )

        val model = NativeRootCardModelMapper().map(report)

        assertEquals(DetectionSeverity.WARNING, model.status.severity)
        assertEquals("1 native signal(s) need review", model.verdict)
        assertEquals("None", model.headerFacts.single { it.fact == NativeRootHeaderFact.FLAGS }.value)
        assertEquals(DetectionSeverity.WARNING, model.nativeRows.single().status.severity)
        val method = model.methodRows.single { it.label == NativeRootMethod.NR_SUPERCALL_PROBE.label }
        assertEquals("Elevated ratio", method.value)
        assertEquals(DetectionSeverity.INFO, method.status.severity)
        assertEquals(InfoKind.SUPPORT, method.status.infoKind)

        val exported = model.toDetectorReport()

        assertEquals(DetectionSeverity.WARNING, exported.severity)
        assertEquals("1 native signal(s) need review", exported.verdict)
        assertEquals("None", exported.quickFacts.single { it.label == NativeRootHeaderFact.FLAGS.label }.value)
        val blocks = exported.blocks.filterIsInstance<ReportBlock.Rows>()
        val nativeRow = blocks.single { it.title == "Native" }.rows.single()
        assertEquals(finding.label, nativeRow.label)
        assertEquals("Elevated ratio (supporting evidence)", nativeRow.value)
        assertEquals(detail, nativeRow.detail)
        val methodRow = blocks.single { it.title == "Methods" }.rows
            .single { it.label == NativeRootMethod.NR_SUPERCALL_PROBE.label }
        assertEquals("Elevated ratio", methodRow.value)
        assertEquals(detail, methodRow.detail)
    }
}
