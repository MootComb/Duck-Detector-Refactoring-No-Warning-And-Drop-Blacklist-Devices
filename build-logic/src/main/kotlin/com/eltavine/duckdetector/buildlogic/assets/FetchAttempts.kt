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

/** The outcome of fetching an asset with retries. */
internal sealed interface FetchOutcome<out T> {
    class Fetched<T>(val value: T, val attempt: Int) : FetchOutcome<T>

    class Failed(val lastFailure: Throwable?) : FetchOutcome<Nothing>
}

/**
 * Calls [fetch] up to [attempts] times, at least once, and returns its first result. After a failed
 * attempt it reports the failure's reason with [warn] and, when another attempt follows, waits
 * [backoffMillis] of that attempt's number.
 */
internal fun <T : Any> fetchWithRetries(
    attempts: Int,
    backoffMillis: (attempt: Int) -> Long,
    warn: (attempt: Int, reason: String) -> Unit,
    fetch: () -> T,
): FetchOutcome<T> {
    val total = attempts.coerceAtLeast(1)
    var lastFailure: Throwable? = null
    for (attempt in 1..total) {
        val result = runCatching(fetch)
        result.getOrNull()?.let { return FetchOutcome.Fetched(it, attempt) }
        lastFailure = result.exceptionOrNull()
        warn(attempt, failureReason(lastFailure))
        if (attempt < total) {
            Thread.sleep(backoffMillis(attempt))
        }
    }
    return FetchOutcome.Failed(lastFailure)
}

/** A failure's message, or its class name when it has none; build tooling runs unminified on the host. */
internal fun failureReason(failure: Throwable?): String = failure?.message ?: failure?.javaClass?.simpleName.orEmpty()
