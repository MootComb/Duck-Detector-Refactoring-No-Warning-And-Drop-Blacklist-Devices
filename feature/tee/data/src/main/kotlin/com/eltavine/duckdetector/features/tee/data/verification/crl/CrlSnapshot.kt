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

package com.eltavine.duckdetector.features.tee.data.verification.crl

internal sealed interface CrlSnapshotResult {
    data class Success(val entries: Map<String, CrlEntry>) : CrlSnapshotResult

    data class Failure(val failure: CrlFailure) : CrlSnapshotResult
}

internal data class CrlFailure(
    val summary: String,
    val detail: String? = null,
) {
    fun withPreflightDetail(preflightDetail: String?): CrlFailure {
        if (preflightDetail.isNullOrBlank()) {
            return this
        }
        return copy(
            detail = listOf(preflightDetail, detail).filterNotNull().joinToString(separator = " ")
        )
    }
}

internal data class CrlEntry(
    val status: String,
    val reason: String?,
    val source: CrlEntrySource,
)

internal enum class CrlEntrySource {
    EMBEDDED,
    ONLINE,
}
