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

package com.eltavine.duckdetector.core.detector

import android.content.Context
import android.content.ContextWrapper
import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.report.DetectorHeadline
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.core.report.DetectorResult
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

class DetectorRunTest {

    @Test
    fun `run scans with a fresh scanner and reports the card verdict and export`() = runTest {
        val detector = CountingDetector()
        val context = ContextWrapper(null)

        val first = detector.run(context)
        val second = detector.run(context)

        assertEquals(2, detector.scannersCreated)
        assertSame(context, detector.lastContext)
        assertEquals(
            DetectorResult(
                id = DetectorId("counting"),
                status = DetectorStatus.warning(),
                report = DetectorReport(
                    title = "Counting",
                    verdict = "scan 1",
                    severity = DetectionSeverity.WARNING,
                    quickFacts = emptyList(),
                    blocks = emptyList(),
                ),
            ),
            first,
        )
        assertEquals("scan 2", second.report.verdict)
    }

    @Test
    fun `a headline has no finding detail unless it states one`() {
        assertNull(Card("any").findingDetail)
    }

    private data class Card(override val verdict: String) : DetectorHeadline {
        override val title: String = "Counting"
        override val status: DetectorStatus = DetectorStatus.warning()
        override val summary: String = "summary"
    }

    private class CountingDetector : Detector<Int, Card> {
        var scannersCreated = 0
        var lastContext: Context? = null

        override val id: DetectorId = DetectorId("counting")

        override fun createScanner(context: Context): DetectorScanner<Int> {
            lastContext = context
            val scan = ++scannersCreated
            return DetectorScanner { scan }
        }

        override fun loadingReport(): Int = 0

        override fun describe(report: Int): Card = Card("scan $report")

        override fun export(model: Card): DetectorReport = DetectorReport(
            title = model.title,
            verdict = model.verdict,
            severity = model.status.severity,
            quickFacts = emptyList(),
            blocks = emptyList(),
        )
    }
}
