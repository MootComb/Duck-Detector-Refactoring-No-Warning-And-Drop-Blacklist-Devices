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

package com.eltavine.duckdetector.features.customrom.domain

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import org.junit.Assert.assertEquals
import org.junit.Test

class CustomRomReportStatusTest {

    private val fullCoverage = CustomRomReport.loading().copy(
        stage = CustomRomStage.READY,
        packageVisibility = CustomRomPackageVisibility.FULL,
        nativeAvailable = true,
        propertyAreaAvailable = true,
        symbolScanAvailable = true,
        serviceScanAvailable = true,
    )

    @Test
    fun `full coverage without findings is clear`() {
        assertEquals(DetectorStatus.allClear(), fullCoverage.toDetectorStatus())
    }

    @Test
    fun `an unqueried ServiceManager is reduced coverage, not a clean result`() {
        assertEquals(
            DetectorStatus.info(InfoKind.SUPPORT),
            fullCoverage.copy(serviceScanAvailable = false).toDetectorStatus(),
        )
    }
}
