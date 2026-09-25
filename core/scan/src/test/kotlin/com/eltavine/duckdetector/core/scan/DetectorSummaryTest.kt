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

package com.eltavine.duckdetector.core.scan

import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.core.report.DetectorHeadline
import org.junit.Assert.assertEquals
import org.junit.Test

class DetectorSummaryTest {

    @Test
    fun `summarizes a headline field by field`() {
        val headline = Headline(findingDetail = "short")

        assertEquals(
            DetectorSummary(
                id = DetectorId("probe"),
                title = "Probe",
                status = DetectorStatus.info(InfoKind.SUPPORT),
                headline = "Verdict",
                summary = "Summary",
                ready = true,
                findingDetail = "short",
            ),
            headline.summarize(DetectorId("probe"), ready = true),
        )
    }

    @Test
    fun `a headline without a finding detail summarizes without one`() {
        val summary = object : DetectorHeadline {
            override val title = "Probe"
            override val status = DetectorStatus.allClear()
            override val verdict = "Clean"
            override val summary = "Nothing found"
        }.summarize(DetectorId("probe"), ready = false)

        assertEquals(null, summary.findingDetail)
        assertEquals(false, summary.ready)
    }

    private data class Headline(override val findingDetail: String?) : DetectorHeadline {
        override val title = "Probe"
        override val status = DetectorStatus.info(InfoKind.SUPPORT)
        override val verdict = "Verdict"
        override val summary = "Summary"
    }
}
