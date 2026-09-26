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

package com.eltavine.duckdetector.buildlogic.assets

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class FetchAttemptsTest {

    @Test
    fun `the first success ends the attempts and names its number`() {
        val warnings = mutableListOf<String>()
        val backoffs = mutableListOf<Int>()
        var calls = 0

        val outcome = fetchWithRetries(4, { backoffs += it; 0L }, { attempt, reason -> warnings += "$attempt:$reason" }) {
            calls++
            if (calls < 3) throw IOException("down $calls") else "body"
        }

        outcome as FetchOutcome.Fetched
        assertEquals("body", outcome.value)
        assertEquals(3, outcome.attempt)
        assertEquals(listOf("1:down 1", "2:down 2"), warnings)
        assertEquals(listOf(1, 2), backoffs)
    }

    @Test
    fun `every failure is reported and the last one is kept, without a wait after it`() {
        val failure = IllegalStateException()
        val warnings = mutableListOf<String>()
        val backoffs = mutableListOf<Int>()

        val outcome = fetchWithRetries<String>(2, { backoffs += it; 0L }, { attempt, reason -> warnings += "$attempt:$reason" }) {
            throw failure
        }

        assertSame(failure, (outcome as FetchOutcome.Failed).lastFailure)
        assertEquals(listOf("1:IllegalStateException", "2:IllegalStateException"), warnings)
        assertEquals(listOf(1), backoffs)
    }

    @Test
    fun `fewer than one attempt still fetches once`() {
        assertTrue(fetchWithRetries(0, { 0L }, { _, _ -> }) { "once" } is FetchOutcome.Fetched)
    }
}
