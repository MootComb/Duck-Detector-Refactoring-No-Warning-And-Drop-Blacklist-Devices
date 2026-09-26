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

package com.eltavine.duckdetector.core.detector

import android.content.Context
import kotlinx.coroutines.flow.Flow

/** Identifies one consent a detector asks for, so that a host can match its prompt and its setting. */
@JvmInline
public value class ConsentId(public val value: String) {
    init {
        require(FORMAT.matches(value)) { "Consent ids are lowercase snake_case, got '$value'" }
    }

    private companion object {
        val FORMAT = Regex("[a-z][a-z0-9]*(_[a-z0-9]+)*")
    }
}

public enum class ConsentDecision {
    UNDECIDED,
    GRANTED,
    DECLINED,
}

/**
 * A choice the user makes about what a detector may do, such as TEE's online revocation refresh.
 *
 * The detector stores the decision and reads it during its scans. A host asks the user, records the
 * answer with [decide] and rescans the detector; the application's startup policy and settings do
 * exactly that. Declining never stops a detector from scanning, it only limits what the scan may do.
 */
public interface DetectorConsent {
    public val id: ConsentId

    /** The current decision; the flow emits again whenever the decision changes. */
    public fun decisions(context: Context): Flow<ConsentDecision>

    public suspend fun decide(context: Context, granted: Boolean)
}
