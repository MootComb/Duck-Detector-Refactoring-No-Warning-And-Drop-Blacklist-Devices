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

package com.eltavine.duckdetector.features.memory.presentation

import com.eltavine.duckdetector.features.memory.domain.MemoryFinding
import com.eltavine.duckdetector.features.memory.domain.MemoryFindingSection
import com.eltavine.duckdetector.features.memory.domain.MemoryFindingSeverity
import com.eltavine.duckdetector.features.memory.domain.MemoryMethod
import com.eltavine.duckdetector.features.memory.domain.MemoryMethodOutcome
import com.eltavine.duckdetector.features.memory.domain.MemoryMethodResult
import com.eltavine.duckdetector.features.memory.domain.MemoryReport
import com.eltavine.duckdetector.features.memory.domain.MemoryStage
import com.eltavine.duckdetector.features.memory.presentation.model.MemoryRowIcon
import org.junit.Assert.assertEquals
import org.junit.Test

class MemoryCardRowIconTest {

    private val mapper = MemoryCardModelMapper()

    @Test
    fun `vDSO and signal findings carry their icons and other findings carry none`() {
        val model = mapper.map(
            MemoryReport.loading().copy(
                stage = MemoryStage.READY,
                findings = listOf(
                    finding(MemoryFindingSection.VDSO, "vDSO base mismatch"),
                    finding(MemoryFindingSection.SIGNAL, "Anonymous signal handler"),
                    finding(MemoryFindingSection.LINKER, "Hidden loader entry"),
                ),
            ),
        )

        assertEquals(
            mapOf(
                "vDSO base mismatch" to MemoryRowIcon.VDSO,
                "Anonymous signal handler" to MemoryRowIcon.SIGNAL_HANDLER,
                "Hidden loader entry" to null,
            ),
            model.loaderRows.associate { it.label to it.icon },
        )
    }

    @Test
    fun `the signal handler method carries the signal icon, loading or ready`() {
        val loading = mapper.map(MemoryReport.loading())
        val ready = mapper.map(
            MemoryReport.loading().copy(
                stage = MemoryStage.READY,
                methods = MemoryMethod.entries.map { method ->
                    MemoryMethodResult(method, "Clean", MemoryMethodOutcome.CLEAN, "detail")
                },
            ),
        )

        listOf(loading, ready).forEach { model ->
            assertEquals(
                listOf(null, null, null, null, MemoryRowIcon.SIGNAL_HANDLER, null),
                model.methodRows.map { it.icon },
            )
            assertEquals(MemoryMethod.entries.map { it.label }, model.methodRows.map { it.label })
        }
    }

    private fun finding(section: MemoryFindingSection, label: String) = MemoryFinding(
        id = label,
        section = section,
        category = section.name,
        label = label,
        detail = "detail",
        severity = MemoryFindingSeverity.MEDIUM,
        detailMonospace = false,
    )
}
