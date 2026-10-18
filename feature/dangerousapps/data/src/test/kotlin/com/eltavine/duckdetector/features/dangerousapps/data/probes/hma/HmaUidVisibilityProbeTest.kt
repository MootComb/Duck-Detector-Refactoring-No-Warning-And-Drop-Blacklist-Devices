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

package com.eltavine.duckdetector.features.dangerousapps.data.probes.hma

import com.eltavine.duckdetector.features.dangerousapps.domain.*
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
import kotlin.coroutines.cancellation.CancellationException

class HmaUidVisibilityProbeTest {
    private open class Calls : HmaUidPackageCalls {
        override fun packages(uid: Int) = if (uid == 10042) listOf("caller") else emptyList()
        override fun permission(uid: Int, permission: String) = false
    }
    private fun probe(calls: HmaUidPackageCalls) = HmaUidVisibilityProbe(10042, "caller", { first, last ->
        UidTaskSnapshot(HmaUidTaskBridge.COMPLETE, last - first + 1,
            tasks = if (first == last) mapOf(first to 0) else mapOf(10042 to 0, 10043 to 0))
    }, calls)

    @Test fun `a fresh association appearing on recheck suppresses a stale missing hit`() = runTest {
        val calls = object : Calls() {
            var reads = 0
            override fun packages(uid: Int): List<String> =
                if (uid == 10043 && ++reads > 1) listOf("visible.now") else super.packages(uid)
        }
        assertTrue(probe(calls).run(DangerousPackageVisibility.FULL).uids.isEmpty())
    }

    @Test fun `a failed fresh association recheck is inconclusive`() = runTest {
        val calls = object : Calls() {
            override fun packages(uid: Int): List<String> =
                if (uid == 10043) throw SecurityException() else super.packages(uid)
        }
        val result = probe(calls).run(DangerousPackageVisibility.FULL)
        assertEquals(HmaCheckState.PERMISSION_LIMITED, result.state)
        assertTrue(result.uids.isEmpty())
    }

    @Test fun `cancellation is not converted to an unavailable association`() = runTest {
        val calls = object : Calls() {
            override fun packages(uid: Int): List<String> = throw CancellationException("cancelled")
        }
        try { probe(calls).run(DangerousPackageVisibility.FULL); fail("Cancellation swallowed") }
        catch (_: CancellationException) { }
    }
    @Test fun `an unavailable private method in a caller control remains unavailable`() = runTest {
        val calls = object : Calls() {
            override fun packages(uid: Int): List<String> = throw NoSuchMethodException("getPackagesForUid")
        }
        val result = probe(calls).run(DangerousPackageVisibility.FULL)
        assertEquals(HmaCheckState.UNAVAILABLE, result.state)
        assertTrue(result.uids.isEmpty())
    }
}
