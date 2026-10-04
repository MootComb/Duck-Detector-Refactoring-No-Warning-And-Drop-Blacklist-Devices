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

package com.eltavine.duckdetector.features.kernelcheck.data.rules

import com.eltavine.duckdetector.features.kernelcheck.data.native.Arm64CpuIdentityObservation
import com.eltavine.duckdetector.features.kernelcheck.data.native.Arm64CpuIdentityProbeStatus
import com.eltavine.duckdetector.features.kernelcheck.data.native.CachedCpuIdentitySource
import com.eltavine.duckdetector.features.kernelcheck.data.native.MrsReadState
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckMethodOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class Arm64CpuIdentityConsistencyEvaluatorTest {

    private val evaluator = Arm64CpuIdentityConsistencyEvaluator()

    @Test
    fun `heterogeneous cores are compared only against themselves`() {
        val assessment = evaluator.evaluate(
            status = Arm64CpuIdentityProbeStatus.COMPLETED,
            observations = listOf(
                observation(cpu = 0, cached = 0x410fd050, mrs = 0x410fd050),
                observation(cpu = 7, cached = 0x410fd480, mrs = 0x410fd480),
            ),
        )

        assertNull(assessment.finding)
        assertEquals(KernelCheckMethodOutcome.CLEAN, assessment.method.outcome)
        assertEquals("2 CPU(s) agree", assessment.method.summary)
    }

    @Test
    fun `one partial core mismatch is a hard detection`() {
        val assessment = evaluator.evaluate(
            status = Arm64CpuIdentityProbeStatus.COMPLETED,
            observations = listOf(
                observation(cpu = 0, cached = 0x410fd050, mrs = 0x410fd050),
                observation(cpu = 7, cached = 0x410fd050, mrs = 0x410fd480),
            ),
        )

        assertNotNull(assessment.finding)
        assertEquals(KernelCheckMethodOutcome.DETECTED, assessment.method.outcome)
        assertEquals("1 core mismatch(es)", assessment.finding?.value)
    }

    @Test
    fun `architecture bits are excluded from proc cpuinfo comparison`() {
        val assessment = evaluator.evaluate(
            status = Arm64CpuIdentityProbeStatus.COMPLETED,
            observations = listOf(
                observation(
                    cpu = 0,
                    cached = 0x4100d050,
                    mrs = 0x410fd050,
                    source = CachedCpuIdentitySource.PROC_CPUINFO,
                ),
            ),
        )

        assertNull(assessment.finding)
        assertEquals(KernelCheckMethodOutcome.CLEAN, assessment.method.outcome)
    }

    @Test
    fun `sysfs comparison keeps architecture bits`() {
        val assessment = evaluator.evaluate(
            status = Arm64CpuIdentityProbeStatus.COMPLETED,
            observations = listOf(
                observation(cpu = 0, cached = 0x4100d050, mrs = 0x410fd050),
            ),
        )

        assertNotNull(assessment.finding)
    }

    @Test
    fun `missing mrs support is not reported as suspicious`() {
        val assessment = evaluator.evaluate(
            status = Arm64CpuIdentityProbeStatus.COMPLETED,
            observations = listOf(
                observation(cpu = 0, cached = 0x410fd050, mrs = null),
            ),
        )

        assertNull(assessment.finding)
        assertEquals(KernelCheckMethodOutcome.SUPPORT, assessment.method.outcome)
    }

    @Test
    fun `one comparable cpu does not make partial coverage clean`() {
        val assessment = evaluator.evaluate(
            status = Arm64CpuIdentityProbeStatus.COMPLETED,
            observations = listOf(
                observation(cpu = 0, cached = 0x410fd050, mrs = 0x410fd050),
                observation(cpu = 7, cached = 0x410fd480, mrs = null),
            ),
        )

        assertNull(assessment.finding)
        assertEquals(KernelCheckMethodOutcome.SUPPORT, assessment.method.outcome)
        assertEquals("Partial (1/2 CPUs)", assessment.method.summary)
    }

    @Test
    fun `affinity failure keeps otherwise matching scan partial`() {
        val assessment = evaluator.evaluate(
            status = Arm64CpuIdentityProbeStatus.COMPLETED,
            observations = listOf(
                observation(cpu = 0, cached = 0x410fd050, mrs = 0x410fd050),
                observation(
                    cpu = 7,
                    cached = null,
                    mrs = null,
                    affinitySucceeded = false,
                ),
            ),
        )

        assertEquals(KernelCheckMethodOutcome.SUPPORT, assessment.method.outcome)
        assertEquals("Partial (1/2 CPUs)", assessment.method.summary)
    }

    @Test
    fun `a kernel without cpuid emulation is named instead of reported as unavailable`() {
        val assessment = evaluator.evaluate(
            status = Arm64CpuIdentityProbeStatus.CPUID_EMULATION_UNAVAILABLE,
            observations = listOf(
                observation(cpu = 0, cached = 0x410fd050, mrs = null),
                observation(cpu = 7, cached = 0x410fd480, mrs = null),
            ),
        )

        assertNull(assessment.finding)
        assertEquals(KernelCheckMethodOutcome.SUPPORT, assessment.method.outcome)
        assertEquals("CPUID emulation unavailable", assessment.method.summary)
        assertTrue(assessment.method.detail.orEmpty().contains("HWCAP_CPUID"))
        // The cached identity each core reports is still worth showing.
        assertTrue(assessment.method.detail.orEmpty().contains("0x410fd480"))
    }

    @Test
    fun `an unknown future status stays a support outcome`() {
        val assessment = evaluator.evaluate(
            status = Arm64CpuIdentityProbeStatus.UNKNOWN,
            observations = emptyList(),
        )

        assertNull(assessment.finding)
        assertEquals(KernelCheckMethodOutcome.SUPPORT, assessment.method.outcome)
    }

    @Test
    fun `a read that ran on another core is not compared with the pinned core`() {
        // The thread was moved from a little core to a big one, so the value it read is the big
        // core's identity and says nothing about the little core's cached identity.
        val assessment = evaluator.evaluate(
            status = Arm64CpuIdentityProbeStatus.COMPLETED,
            observations = listOf(
                observation(
                    cpu = 0,
                    cached = 0x410fd050,
                    mrs = 0x410fd480,
                    state = MrsReadState.UNATTRIBUTED,
                    readsOffCpu = 6,
                ),
                observation(cpu = 7, cached = 0x410fd480, mrs = 0x410fd480),
            ),
        )

        assertNull(assessment.finding)
        assertEquals(KernelCheckMethodOutcome.SUPPORT, assessment.method.outcome)
        assertEquals("Partial (1/2 CPUs)", assessment.method.summary)
        assertTrue(assessment.method.detail.orEmpty().contains("not confirmed on this CPU (6 ran elsewhere)"))
    }

    @Test
    fun `reads that disagree on one core are inconclusive rather than a detection`() {
        val assessment = evaluator.evaluate(
            status = Arm64CpuIdentityProbeStatus.COMPLETED,
            observations = listOf(
                observation(cpu = 0, cached = 0x410fd050, mrs = null, state = MrsReadState.UNSTABLE),
            ),
        )

        assertNull(assessment.finding)
        assertEquals(KernelCheckMethodOutcome.SUPPORT, assessment.method.outcome)
        assertTrue(assessment.method.detail.orEmpty().contains("changed between reads"))
    }

    @Test
    fun `a verified mismatch is detected even after reads were discarded`() {
        val assessment = evaluator.evaluate(
            status = Arm64CpuIdentityProbeStatus.COMPLETED,
            observations = listOf(
                observation(cpu = 0, cached = 0x410fd050, mrs = 0x410fd050),
                observation(cpu = 7, cached = 0x411fd4f0, mrs = 0x410fd480, readsOffCpu = 2),
            ),
        )

        assertNotNull(assessment.finding)
        assertEquals(KernelCheckMethodOutcome.DETECTED, assessment.method.outcome)
        assertEquals("1 core mismatch(es)", assessment.finding?.value)
    }

    @Test
    fun `a faulted read is reported as unavailable`() {
        val assessment = evaluator.evaluate(
            status = Arm64CpuIdentityProbeStatus.COMPLETED,
            observations = listOf(
                observation(cpu = 0, cached = 0x410fd050, mrs = null, state = MrsReadState.FAULTED),
            ),
        )

        assertNull(assessment.finding)
        assertEquals(KernelCheckMethodOutcome.SUPPORT, assessment.method.outcome)
        assertTrue(assessment.method.detail.orEmpty().contains("MRS MIDR_EL1 unavailable"))
    }

    private fun observation(
        cpu: Int,
        cached: Long?,
        mrs: Long?,
        source: CachedCpuIdentitySource = CachedCpuIdentitySource.SYSFS,
        affinitySucceeded: Boolean = true,
        state: MrsReadState = if (mrs != null) MrsReadState.VERIFIED else MrsReadState.NOT_ATTEMPTED,
        readsOffCpu: Int = 0,
    ): Arm64CpuIdentityObservation {
        return Arm64CpuIdentityObservation(
            cpu = cpu,
            affinitySucceeded = affinitySucceeded,
            cachedSource = source,
            cachedMidr = cached,
            mrsMidr = mrs,
            mrsReadState = state,
            readsOffCpu = readsOffCpu,
        )
    }
}
