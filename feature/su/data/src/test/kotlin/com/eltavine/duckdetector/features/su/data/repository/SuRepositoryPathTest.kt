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

package com.eltavine.duckdetector.features.su.data.repository

import com.eltavine.duckdetector.core.platform.PathState
import com.eltavine.duckdetector.features.su.domain.SuMethodOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

// The file scan also walks the host's PATH and runs `which su`, so only the daemon scan, which
// reads nothing but the injected path states, is asserted here.
class SuRepositoryPathTest {

    @Test
    fun `daemon paths this app cannot stat leave the daemon scan partial`() {
        val report = SuRepository(
            pathState = { path -> if (path.startsWith("/data/adb")) PathState.NOT_OBSERVABLE else PathState.ABSENT },
        ).scanInternal()

        val daemonScan = report.methods.single { it.label == "daemonScan" }
        assertEquals("Partial", daemonScan.summary)
        assertEquals(SuMethodOutcome.SUPPORT, daemonScan.outcome)
        assertTrue(report.unobservablePathCount > 0)
        assertEquals(0, report.checkedDaemonPathCount)
    }

    @Test
    fun `absent daemon paths keep the daemon scan clean`() {
        val report = SuRepository(pathState = { PathState.ABSENT }).scanInternal()

        val daemonScan = report.methods.single { it.label == "daemonScan" }
        assertEquals(SuMethodOutcome.CLEAN, daemonScan.outcome)
        assertEquals(0, report.unobservablePathCount)
    }

    @Test
    fun `a daemon that can be stat-ed is detected`() {
        val report = SuRepository(
            pathState = { path -> if (path == "/data/adb/ksud") PathState.PRESENT else PathState.ABSENT },
        ).scanInternal()

        assertEquals(SuMethodOutcome.DETECTED, report.methods.single { it.label == "daemonScan" }.outcome)
    }
}
