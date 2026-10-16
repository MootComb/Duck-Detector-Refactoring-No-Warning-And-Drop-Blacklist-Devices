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

package com.eltavine.duckdetector.features.heapresidue.data

/**
 * Byte and count budgets shared by the streaming parser and the local retention tee.
 *
 * The tee must never drop a dump the parser accepted. A smaller spool than the parser's budget
 * produced snapshots that were parsed and reported as complete but silently deleted before the
 * `.part` spool could be renamed, so [SPOOL_CAPACITY_BYTES] tracks [PARSE_BUDGET_BYTES] instead of
 * a separate, smaller value. Equalling the parse budget also aligns the two over-budget boundaries:
 * `TOO_LARGE` and the parser's byte-limit failure fire on the same input rather than drifting apart.
 *
 * Real isolated-process dumps measured at a minimum of 57 MB; the cap is a ceiling that is only
 * reached on FLAG_DEBUGGABLE hosts, not an allocation.
 */
internal object HeapDumpBudgets {
    /** Bytes consumed from one dump. Bounds parser work, not memory. */
    const val PARSE_BUDGET_BYTES: Long = 256L * 1024 * 1024

    /** Largest single retained dump. Invariant: never below [PARSE_BUDGET_BYTES]. */
    const val SPOOL_CAPACITY_BYTES: Long = PARSE_BUDGET_BYTES

    /** Completed dumps kept on device. */
    const val RETAINED_DUMP_COUNT: Int = 2

    /** Worst case of [RETAINED_DUMP_COUNT] full spools. */
    const val DIRECTORY_BUDGET_BYTES: Long = SPOOL_CAPACITY_BYTES * RETAINED_DUMP_COUNT
}
