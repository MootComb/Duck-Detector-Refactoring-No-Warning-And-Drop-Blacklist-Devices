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

package com.eltavine.duckdetector.integration.dashboard

import com.eltavine.duckdetector.features.dashboard.data.DashboardReportRenderer
import com.eltavine.duckdetector.features.dashboard.data.ExportHeader
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class DashboardExportGoldenTest {

    @Test
    fun `typed report matches the golden export`() {
        val rendered = GOLDEN_SEEDS.joinToString(separator = "\n# ---- next scenario ----\n") { seed ->
            DashboardReportRenderer.render(ExportScenario(seed, minListSize = seed % 2 * 2).export(FIXED_HEADER))
        }
        if (System.getenv("DD_UPDATE_GOLDEN") == "1") {
            File("src/test/resources/$GOLDEN_RESOURCE").apply { parentFile.mkdirs() }.writeText(rendered)
            return
        }
        val golden = javaClass.getResource("/$GOLDEN_RESOURCE")?.readText()

        assertNotNull("missing golden export $GOLDEN_RESOURCE", golden)
        assertEquals(golden, rendered)
    }

    private companion object {
        val GOLDEN_SEEDS = 0 until 4
        const val GOLDEN_RESOURCE = "dashboard-export/golden-report.txt"
        val FIXED_HEADER = ExportHeader(
            versionName = "2026.01.02-0123456789ab",
            versionCode = 321,
            buildHash = "0123456789ab",
            buildTime = "2026-01-02 03:04:05",
            reportTime = "2026-01-02 03:04:05 (UTC)",
        )
    }
}
