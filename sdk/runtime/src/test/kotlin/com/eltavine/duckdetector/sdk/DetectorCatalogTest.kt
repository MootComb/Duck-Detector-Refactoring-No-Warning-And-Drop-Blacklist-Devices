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

package com.eltavine.duckdetector.sdk

import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.report.DetectorHeadline
import org.junit.Assert.assertEquals
import org.junit.Test

class DetectorCatalogTest {

    private val ids = DetectorCatalog.all.map { it.id.value }

    @Test
    fun `every detector appears once`() {
        assertEquals(ids.distinct(), ids)
    }

    @Test
    fun `every consent id appears once across the catalog`() {
        val consentIds = DetectorCatalog.all.flatMap { detector -> detector.consents.map { it.id } }
        assertEquals(consentIds.distinct(), consentIds)
    }

    @Test
    fun `bootloader and TEE start first and every other detector follows by id`() {
        assertEquals(listOf("bootloader", "tee"), ids.take(2))
        assertEquals(ids.drop(2).sorted(), ids.drop(2))
    }

    @Test
    fun `every detector describes and exports its loading report under its own title`() {
        DetectorCatalog.all.forEach { detector ->
            val (card, export) = loadingCardAndExport(detector)
            assertEquals(detector.id.value, card.title, export.title)
            assertEquals(detector.id.value, card.status.severity, export.severity)
            assertEquals(detector.id.value, card.verdict, export.verdict)
        }
    }

    private fun <R : Any, M : DetectorHeadline> loadingCardAndExport(detector: Detector<R, M>) =
        detector.describe(detector.loadingReport()).let { card -> card to detector.export(card) }
}
