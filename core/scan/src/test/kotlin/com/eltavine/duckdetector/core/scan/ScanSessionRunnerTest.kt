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

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ScanSessionRunnerTest {

    private val events = mutableListOf<String>()

    @Test
    fun `runs begin, collect and publish in order`() = runTest(UnconfinedTestDispatcher()) {
        val runner = ScanSessionRunner(backgroundScope)

        runner.launch(
            begin = { events += "begin" },
            collect = { events += "collect"; "report" },
            publish = { events += "publish $it" },
        )

        assertEquals(listOf("begin", "collect", "publish report"), events)
    }

    @Test
    fun `begin is visible before the request first suspends`() = runTest(UnconfinedTestDispatcher()) {
        val runner = ScanSessionRunner(backgroundScope)
        val gate = CompletableDeferred<String>()

        runner.launch(begin = { events += "begin" }, collect = { gate.await() }, publish = { events += it })

        assertEquals(listOf("begin"), events)
        gate.complete("done")
        assertEquals(listOf("begin", "done"), events)
    }

    @Test
    fun `newer request suppresses the older result and waits for the running scan`() =
        runTest(UnconfinedTestDispatcher()) {
            val runner = ScanSessionRunner(backgroundScope)
            val first = CompletableDeferred<String>()
            val second = CompletableDeferred<String>()

            runner.launch(begin = { events += "begin 1" }, collect = { events += "collect 1"; first.await() }, publish = { events += "publish $it" })
            runner.launch(begin = { events += "begin 2" }, collect = { events += "collect 2"; second.await() }, publish = { events += "publish $it" })

            assertEquals(listOf("begin 1", "collect 1", "begin 2"), events)
            first.complete("stale")
            assertEquals(listOf("begin 1", "collect 1", "begin 2", "collect 2"), events)
            second.complete("fresh")
            assertEquals(listOf("begin 1", "collect 1", "begin 2", "collect 2", "publish fresh"), events)
        }

    @Test
    fun `requests superseded while queued never collect`() = runTest(UnconfinedTestDispatcher()) {
        val runner = ScanSessionRunner(backgroundScope)
        val running = CompletableDeferred<String>()
        var collections = 0

        runner.launch(begin = {}, collect = { collections++; running.await() }, publish = { events += it })
        runner.launch(begin = {}, collect = { collections++; "queued" }, publish = { events += it })
        val newest = runner.launch(begin = {}, collect = { collections++; "newest" }, publish = { events += it })
        running.complete("stale")

        assertEquals(2, collections)
        assertEquals(listOf("newest"), events)
        assertTrue(runner.isNewest(newest))
    }

    @Test
    fun `a failed scan releases admission for the next request`() {
        val failures = mutableListOf<Throwable>()
        val scope = CoroutineScope(
            UnconfinedTestDispatcher() + SupervisorJob() + CoroutineExceptionHandler { _, error -> failures += error },
        )
        val runner = ScanSessionRunner(scope)

        runner.launch(begin = {}, collect = { error("probe crashed") }, publish = { events += "unexpected" })
        runner.launch(begin = {}, collect = { "recovered" }, publish = { events += it })

        assertEquals(listOf("probe crashed"), failures.map { it.message })
        assertEquals(listOf("recovered"), events)
        scope.cancel()
    }

    @Test
    fun `cancelling the owner scope stops publication`() = runTest {
        val scope = CoroutineScope(StandardTestDispatcher(testScheduler) + Job())
        val runner = ScanSessionRunner(scope)
        val gate = CompletableDeferred<String>()

        runner.launch(begin = { events += "begin" }, collect = { gate.await() }, publish = { events += it })
        runCurrent()
        scope.cancel()
        gate.complete("late")
        advanceUntilIdle()

        assertEquals(listOf("begin"), events)
    }

    @Test
    fun `session ids increase and only the latest is newest`() = runTest(UnconfinedTestDispatcher()) {
        val runner = ScanSessionRunner(backgroundScope)

        val first = runner.launch(begin = {}, collect = { 1 }, publish = {})
        val second = runner.launch(begin = {}, collect = { 2 }, publish = {})

        assertTrue(second.value > first.value)
        assertFalse(runner.isNewest(first))
        assertTrue(runner.isNewest(second))
    }
}
