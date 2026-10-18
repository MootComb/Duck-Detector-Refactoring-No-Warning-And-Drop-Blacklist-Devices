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

package com.eltavine.duckdetector.features.dangerousapps.data.probes

import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsCatalog
import com.eltavine.duckdetector.features.dangerousapps.domain.PackageChangeHistoryState
import java.io.IOException
import kotlin.coroutines.cancellation.CancellationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PackageChangeHistoryProbeTest {
    private val target = DangerousAppsCatalog.targets.first { it.packageName == "com.tsng.hidemyapplist" }

    @Test fun `keeps only exact monitored names once in catalog order`() {
        val other = DangerousAppsCatalog.targets.first()
        val probe = PackageChangeHistoryProbe {
            PackageChangesSnapshot(8, listOf(target.packageName, "${target.packageName}.other",
                "unrelated.package", other.packageName, target.packageName))
        }
        val result = probe.run(listOf(other, target, target))
        assertEquals(PackageChangeHistoryState.AVAILABLE, result.state)
        assertEquals(listOf(other, target), result.matchedTargets)
        assertEquals(8, result.sequenceNumber)
    }

    @Test fun `every scan starts at zero across repeated scans and reboot sequence resets`() {
        val requested = mutableListOf<Int>()
        val replies = listOf(PackageChangesSnapshot(99, listOf(target.packageName)),
            null, PackageChangesSnapshot(2, listOf(target.packageName))).iterator()
        val probe = PackageChangeHistoryProbe { sequence ->
            requested += sequence
            replies.next()
        }
        assertEquals(listOf(target), probe.run(listOf(target)).matchedTargets)
        assertTrue(probe.run(listOf(target)).matchedTargets.isEmpty())
        assertEquals(2, probe.run(listOf(target)).sequenceNumber)
        assertEquals(listOf(0, 0, 0), requested)
    }

    @Test fun `null response has no visible matches and no fabricated sequence`() {
        val result = PackageChangeHistoryProbe { null }.run(listOf(target))
        assertEquals(PackageChangeHistoryState.AVAILABLE, result.state)
        assertTrue(result.matchedTargets.isEmpty())
        assertEquals(null, result.sequenceNumber)
    }

    @Test fun `fully filtered response can retain its sequence without any package names`() {
        val result = PackageChangeHistoryProbe { PackageChangesSnapshot(12, emptyList()) }.run(listOf(target))
        assertEquals(PackageChangeHistoryState.AVAILABLE, result.state)
        assertTrue(result.matchedTargets.isEmpty())
        assertEquals(12, result.sequenceNumber)
    }

    @Test fun `permission denial remains distinct from absent changes`() {
        val result = PackageChangeHistoryProbe { throw SecurityException() }.run(listOf(target))
        assertEquals(PackageChangeHistoryState.PERMISSION_DENIED, result.state)
        assertTrue(result.matchedTargets.isEmpty())
    }

    @Test fun `service failure remains distinct from permission denial and absent changes`() {
        val result = PackageChangeHistoryProbe { throw IOException() }.run(listOf(target))
        assertEquals(PackageChangeHistoryState.UNAVAILABLE, result.state)
    }

    @Test fun `invalid response cannot retain a partially matched target`() {
        listOf(
            PackageChangesSnapshot(-1, listOf(target.packageName)),
            PackageChangesSnapshot(0, listOf(target.packageName)),
            PackageChangesSnapshot(3, listOf(target.packageName, " ")),
            PackageChangesSnapshot(3, listOf(target.packageName, null)),
        ).forEach { snapshot ->
            val result = PackageChangeHistoryProbe { snapshot }.run(listOf(target))
            assertEquals(PackageChangeHistoryState.INVALID_RESPONSE, result.state)
            assertTrue(result.matchedTargets.isEmpty())
            assertEquals(null, result.sequenceNumber)
        }
    }

    @Test(expected = CancellationException::class)
    fun `cancellation is propagated`() {
        PackageChangeHistoryProbe { throw CancellationException() }.run(listOf(target))
    }
}
