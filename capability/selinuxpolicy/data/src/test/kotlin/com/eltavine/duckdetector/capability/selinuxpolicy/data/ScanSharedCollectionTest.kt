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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

class ScanSharedCollectionTest {

    private var now = 0L
    private val shared = ScanSharedCollection<String>(clock = { now })

    @Test
    fun `detectors of the same scan share one collection`() = runTest {
        var collections = 0
        now = 110

        val first = shared.collect(scanStartedAt = 100) { collections++; "snapshot" }
        val second = shared.collect(scanStartedAt = 100) { collections++; "again" }

        assertEquals("snapshot", first)
        assertEquals("snapshot", second)
        assertEquals(1, collections)
    }

    @Test
    fun `a scan that started after the last collection began collects afresh`() = runTest {
        now = 110
        shared.collect(scanStartedAt = 100) { "earlier scan" }

        now = 210
        assertEquals("later scan", shared.collect(scanStartedAt = 200) { "later scan" })
    }

    @Test
    fun `a detector waits for the collection in progress and takes it`() = runTest {
        val collectionDone = CompletableDeferred<Unit>()
        var collections = 0
        now = 110

        val first = async {
            shared.collect(scanStartedAt = 100) {
                collections++
                collectionDone.await()
                "snapshot"
            }
        }
        val second = async { shared.collect(scanStartedAt = 100) { collections++; "again" } }
        runCurrent()
        collectionDone.complete(Unit)

        assertEquals("snapshot", first.await())
        assertEquals("snapshot", second.await())
        assertEquals(1, collections)
    }
}
