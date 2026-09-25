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

package com.eltavine.duckdetector.ui.shell

import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.scan.DetectorSummary
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardOverviewModel
import com.eltavine.duckdetector.features.dashboard.ui.model.OverviewCounts
import com.eltavine.duckdetector.features.dashboard.ui.model.OverviewVerdict
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DetectorResultNoticeDialogTest {

    @Test
    fun `does not show while dashboard is loading`() {
        assertFalse(
            shouldShowDetectorResultNotice(
                isLoading = true,
                overviewStatus = DetectorStatus.danger(),
            ),
        )
    }

    @Test
    fun `does not show when overall result is ok`() {
        assertFalse(
            shouldShowDetectorResultNotice(
                isLoading = false,
                overviewStatus = DetectorStatus.allClear(),
            ),
        )
    }

    @Test
    fun `does not show for info only result`() {
        assertFalse(
            shouldShowDetectorResultNotice(
                isLoading = false,
                overviewStatus = DetectorStatus.info(
                    com.eltavine.duckdetector.core.evidence.InfoKind.ERROR
                ),
            ),
        )
    }

    @Test
    fun `shows when scan is complete and result is warning`() {
        assertTrue(
            shouldShowDetectorResultNotice(
                isLoading = false,
                overviewStatus = DetectorStatus.warning(),
            ),
        )
    }

    @Test
    fun `returns ids of ready danger and warning detectors only`() {
        val ids = attentionDetectorIds(
            listOf(
                DetectorSummary(
                    id = DetectorId("bootloader"),
                    title = "Bootloader",
                    status = DetectorStatus.danger(),
                    headline = "Danger",
                    summary = "summary",
                    ready = true,
                ),
                DetectorSummary(
                    id = DetectorId("tee"),
                    title = "TEE",
                    status = DetectorStatus.warning(),
                    headline = "Warning",
                    summary = "summary",
                    ready = true,
                ),
                DetectorSummary(
                    id = DetectorId("memory"),
                    title = "Memory",
                    status = DetectorStatus.allClear(),
                    headline = "OK",
                    summary = "summary",
                    ready = true,
                ),
                DetectorSummary(
                    id = DetectorId("virtualization"),
                    title = "Virtualization",
                    status = DetectorStatus.danger(),
                    headline = "Danger",
                    summary = "summary",
                    ready = false,
                ),
            ),
        )

        assertEquals(linkedSetOf(DetectorId("bootloader"), DetectorId("tee")), ids)
    }
    @Test
    fun `notice key ignores wording and follows the typed outcome`() {
        val base = noticeOverview(focus = listOf("mount", "tee"), danger = 1)

        assertEquals(
            detectorResultNoticeKey(base),
            detectorResultNoticeKey(base.copy(headline = "Reworded", summary = "Reworded summary", title = "Reworded title")),
        )
        assertNotEquals(detectorResultNoticeKey(base), detectorResultNoticeKey(noticeOverview(focus = listOf("tee", "mount"), danger = 1)))
        assertNotEquals(detectorResultNoticeKey(base), detectorResultNoticeKey(noticeOverview(focus = listOf("mount", "tee"), danger = 2)))
    }

    private fun noticeOverview(focus: List<String>, danger: Int) = DashboardOverviewModel(
        title = "Security overview",
        headline = "Danger",
        summary = "Start with Mount and TEE.",
        status = DetectorStatus.danger(),
        metrics = emptyList(),
        verdict = OverviewVerdict.DANGER,
        titleDescribesCompletedScan = false,
        focusDetectorIds = focus.map(::DetectorId),
        counts = OverviewCounts(danger = danger, warning = 0, ready = 15, pending = 0),
    )
}
