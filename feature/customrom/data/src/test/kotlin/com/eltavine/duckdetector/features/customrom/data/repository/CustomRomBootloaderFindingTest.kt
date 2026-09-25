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

package com.eltavine.duckdetector.features.customrom.data.repository

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class CustomRomBootloaderFindingTest {

    @Test
    fun `an explicitly unlocked value is a finding`() {
        listOf("0", " unlocked ", "FALSE").forEach { value ->
            assertEquals(value, "Unlocked bootloader", bootloaderUnlockFinding(value)?.summary)
        }
    }

    @Test
    fun `a locked, empty, unreadable or unknown value is not`() {
        listOf("1", "locked", "true", "", "   ", null, "2").forEach { value ->
            assertNull("$value", bootloaderUnlockFinding(value))
        }
    }
}
