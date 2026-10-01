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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Gives every detector that reads the carrier during one scan the same collection.
 *
 * The SELinux and LSPosed scans both read the SELinux carrier, and the dashboard and the SDK start
 * them together. A collection that began at or after a caller's own scan start was gathered during
 * that scan, so the caller takes it rather than starting the carrier's app zygote again. One that
 * began earlier belongs to an older scan, and the caller collects afresh.
 */
internal class ScanSharedCollection<T : Any>(
    private val clock: () -> Long,
) {
    private val mutex = Mutex()
    private var latest: Collected<T>? = null

    suspend fun collect(scanStartedAt: Long, collect: suspend () -> T): T = mutex.withLock {
        latest?.takeIf { it.startedAt >= scanStartedAt }?.let { return@withLock it.value }
        val startedAt = clock()
        val value = collect()
        latest = Collected(startedAt, value)
        value
    }

    private class Collected<T>(val startedAt: Long, val value: T)
}
