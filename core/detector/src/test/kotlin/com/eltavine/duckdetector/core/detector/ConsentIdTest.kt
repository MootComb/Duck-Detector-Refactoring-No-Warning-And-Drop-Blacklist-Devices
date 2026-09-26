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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ConsentIdTest {

    @Test
    fun `accepts snake case identifiers`() {
        listOf("revocation_network", "network", "crl2").forEach { value ->
            assertEquals(value, ConsentId(value).value)
        }
    }

    @Test
    fun `rejects identifiers that look like presentation text`() {
        listOf("", "Revocation network", "revocation-network", "_network", "network_", "TEE").forEach { value ->
            assertThrows(IllegalArgumentException::class.java) { ConsentId(value) }
        }
    }
}
