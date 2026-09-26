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

package com.eltavine.duckdetector.core.evidence

/**
 * Stable identity of a detector.
 *
 * Titles are presentation text and may change with wording or localisation; anything that needs
 * to recognise a detector (ordering, auto-expansion, exported sections) keys on this instead.
 */
@JvmInline
public value class DetectorId(public val value: String) {
    init {
        require(FORMAT.matches(value)) { "Detector ids are lowercase snake_case, got '$value'" }
    }

    override fun toString(): String = value

    private companion object {
        val FORMAT = Regex("[a-z][a-z0-9]*(_[a-z0-9]+)*")
    }
}
