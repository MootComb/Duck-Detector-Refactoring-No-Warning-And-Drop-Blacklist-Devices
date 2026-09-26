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

package com.eltavine.duckdetector.core.platform

import android.os.SystemProperties
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Test

class HiddenSystemPropertiesTest {

    @After
    fun reset() {
        SystemProperties.values = emptyMap()
        SystemProperties.lastOverload = null
    }

    @Test
    fun `the single argument read calls get with the key only`() {
        SystemProperties.values = mapOf("ro.build.type" to "user")

        assertEquals("user", HiddenSystemProperties.read("ro.build.type").getOrNull())
        assertEquals("get(key)", SystemProperties.lastOverload)
    }

    @Test
    fun `the default read calls the overload that takes a default`() {
        assertEquals("fallback", HiddenSystemProperties.read("ro.missing", "fallback").getOrNull())
        assertEquals("get(key, def)", SystemProperties.lastOverload)
    }

    @Test
    fun `an unset key reads as empty through the single argument overload`() {
        assertEquals("", HiddenSystemProperties.read("ro.missing").getOrNull())
    }
}
