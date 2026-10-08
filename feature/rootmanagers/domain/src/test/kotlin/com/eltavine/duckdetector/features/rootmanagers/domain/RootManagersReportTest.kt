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

package com.eltavine.duckdetector.features.rootmanagers.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RootManagersReportTest {

    @Test
    fun `only searched profiles count as searched`() {
        val report = evaluated(
            profileScans = listOf(
                searched(0, apps = 3),
                RootManagersProfileScan(10, ProfileScanState.DENIED),
                RootManagersProfileScan(11, ProfileScanState.EMPTY),
            ),
        )

        assertEquals(3, report.profileScans.size)
        assertEquals(1, report.profilesSearched)
        assertEquals(3, report.launcherActivitiesSeen)
        assertEquals(3, report.appsChecked)
        assertFalse(report.complete)
    }

    @Test
    fun `an enumeration that never ran reports no searched profiles and is never complete`() {
        val undecidable = RootManagersReport.undecidable("no profiles")

        assertEquals(0, undecidable.profilesSearched)
        assertEquals(0, undecidable.appsChecked)
        assertFalse(undecidable.complete)
        assertFalse(RootManagersReport.unavailable("denied").complete)
    }

    @Test
    fun `a fully searched, fully visible evaluation is complete`() {
        assertTrue(evaluated().complete)
    }

    @Test
    fun `certificates count as unavailable only when none could be read`() {
        assertTrue(RootManagersCoverage(certificatesRead = 0, certificateReadFailures = 2).certificatesUnavailable)
        assertFalse(RootManagersCoverage(certificatesRead = 5, certificateReadFailures = 2).certificatesUnavailable)
        assertFalse(RootManagersCoverage().certificatesUnavailable)
    }
}
