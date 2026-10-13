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

/** What the disposable child saw when it sent the nonconforming requests to the status node. */
public enum class SelinuxStatusAbiState {
    /** At least one request stock selinuxfs rejects was granted. */
    VIOLATION,

    /** Every nonconforming request was rejected, like stock selinuxfs. */
    NO_VIOLATION,

    /** The node could not be opened or the baseline mapping failed, so no request reached the handler. */
    UNAVAILABLE,

    /** No grant was reported, but the child could not run or finish the request set. */
    INCONCLUSIVE,
}

/** The nonconforming mmap/mprotect requests the probe sends to the status node. */
public enum class SelinuxStatusAbiRequestKind {
    TWO_PAGE_SHARED,
    OFFSET_SHARED,
    WRITABLE_PRIVATE,
    MPROTECT_WRITE,
}

/** The status mmap ABI probe's reading, carried inside [SelinuxContextValiditySnapshot]. */
public data class SelinuxStatusAbiSnapshot(
    val attempted: Boolean = false,
    val state: SelinuxStatusAbiState = SelinuxStatusAbiState.INCONCLUSIVE,
    /** The requests the kernel granted, present when [state] is [SelinuxStatusAbiState.VIOLATION]. */
    val violatedRequests: List<SelinuxStatusAbiRequestKind> = emptyList(),
    val pageSize: Long? = null,
    /** Also retained with VIOLATION when later child failure leaves other requests unevaluated. */
    val failureReason: String? = null,
    val notes: List<String> = emptyList(),
)
