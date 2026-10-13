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

package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStage
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStatusAbiReading
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStatusAbiRequest
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStatusAbiVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxStatusAbiPresentationTest {

    private val mapper = SelinuxCardModelMapper()

    @Test
    fun `a partial violation stays danger and shows the incomplete request reason`() {
        val partial = statusAbiResult(SelinuxStatusAbiVerdict.ABI_VIOLATION, isSecure = false).copy(
            details = "The status node granted requests stock selinuxfs rejects: writable private mmap. " +
                "The request set did not finish: Status ABI child was killed by SIGSEGV.",
        )
        val model = mapper.map(baseReport(partial))
        val row = model.methodRows.single { it.label == SelinuxOracle.STATUS_MMAP_ABI.label }
        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals(DetectorStatus.danger(), row.status)
        assertEquals(partial.details, row.detail)
    }

    @Test
    fun `an ABI violation is danger in the card status and its method row`() {
        val model = mapper.map(
            baseReport(statusAbiResult(verdict = SelinuxStatusAbiVerdict.ABI_VIOLATION, isSecure = false)),
        )

        assertEquals(DetectorStatus.danger(), model.status)
        val row = model.methodRows.single { it.label == SelinuxOracle.STATUS_MMAP_ABI.label }
        assertEquals(DetectorStatus.danger(), row.status)
        assertTrue(row.detail.orEmpty().contains("writable private mmap"))
    }

    @Test
    fun `no violation observed stays clear on its row`() {
        val model = mapper.map(
            baseReport(statusAbiResult(verdict = SelinuxStatusAbiVerdict.NO_VIOLATION, isSecure = null)),
        )

        val row = model.methodRows.single { it.label == SelinuxOracle.STATUS_MMAP_ABI.label }
        assertEquals(DetectorStatus.allClear(), row.status)
        assertEquals(DetectorStatus.allClear(), model.status)
    }

    @Test
    fun `unavailable and inconclusive stay informational`() {
        val model = mapper.map(
            baseReport(statusAbiResult(verdict = SelinuxStatusAbiVerdict.UNAVAILABLE, isSecure = null)),
        )

        val row = model.methodRows.single { it.label == SelinuxOracle.STATUS_MMAP_ABI.label }
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), row.status)
        assertEquals(DetectorStatus.allClear(), model.status)
    }

    private fun statusAbiResult(verdict: SelinuxStatusAbiVerdict, isSecure: Boolean?): SelinuxCheckResult {
        return SelinuxCheckResult(
            method = SelinuxOracle.STATUS_MMAP_ABI.label,
            status = verdict.label,
            isSecure = isSecure,
            permissionDenied = false,
            details = "The status node granted requests stock selinuxfs rejects: writable private mmap.",
            oracle = SelinuxOracle.STATUS_MMAP_ABI,
            statusAbi = SelinuxStatusAbiReading(
                verdict = verdict,
                violatedRequests = if (verdict == SelinuxStatusAbiVerdict.ABI_VIOLATION) {
                    listOf(SelinuxStatusAbiRequest.WRITABLE_PRIVATE)
                } else {
                    emptyList()
                },
                pageSize = 4096,
            ),
        )
    }

    private fun baseReport(vararg methods: SelinuxCheckResult): SelinuxReport {
        return SelinuxReport(
            stage = SelinuxStage.READY,
            mode = SelinuxMode.ENFORCING,
            resolvedStatusLabel = "Enforcing",
            filesystemMounted = true,
            paradoxDetected = false,
            methods = methods.toList(),
            processContext = "u:r:untrusted_app:s0:c1,c2",
            contextType = "untrusted_app",
            policyAnalysis = null,
            auditIntegrity = null,
            androidVersion = "16",
            apiLevel = 36,
        )
    }
}
