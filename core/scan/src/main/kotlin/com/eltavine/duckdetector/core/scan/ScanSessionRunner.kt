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

import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Identity of one scan request made through a [ScanSessionRunner]. */
@JvmInline
public value class ScanSessionId(public val value: Long)

/**
 * Owns the lifecycle of one detector's scans.
 *
 * Probes touch shared process state (Keystore aliases, bound isolated services, timing
 * measurements), so two scans of the same detector must never overlap, and a scan that has
 * started must be allowed to finish its own cleanup rather than be cancelled half way. Requests
 * are therefore serialized: each request publishes its starting state immediately, waits for the
 * previous scan to finish, is skipped if a newer request arrived while it waited, and may publish
 * its result only while it is still the newest request. An older scan can never overwrite the
 * result of a newer one.
 *
 * Cancelling [scope] still cancels everything, which is how the owner's lifetime ends scans.
 */
public class ScanSessionRunner(
    private val scope: CoroutineScope,
) {
    private val admission = Mutex()
    private val newest = AtomicLong(0)

    /**
     * Requests a scan.
     *
     * [begin] runs before the request first suspends, so on an immediate dispatcher the starting
     * state is visible synchronously, exactly as when the owner launched the scan itself.
     */
    public fun <T> launch(
        begin: () -> Unit,
        collect: suspend () -> T,
        publish: (T) -> Unit,
    ): ScanSessionId {
        val session = ScanSessionId(newest.incrementAndGet())
        scope.launch {
            begin()
            admission.withLock {
                if (!isNewest(session)) {
                    return@withLock
                }
                val result = collect()
                if (isNewest(session)) {
                    publish(result)
                }
            }
        }
        return session
    }

    public fun isNewest(session: ScanSessionId): Boolean = newest.get() == session.value
}
