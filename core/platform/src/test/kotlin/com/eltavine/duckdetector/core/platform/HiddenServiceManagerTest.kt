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

import android.os.Binder
import android.os.ServiceManager
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

class HiddenServiceManagerTest {

    @After
    fun reset() {
        ServiceManager.services = emptyMap()
        ServiceManager.listed = emptyArray()
    }

    @Test
    fun `getService returns the registered binder or null`() {
        val binder = Binder()
        ServiceManager.services = mapOf("activity" to binder)

        assertSame(binder, HiddenServiceManager.getService("activity").getOrNull())
        assertNull(HiddenServiceManager.getService("qemud").getOrNull())
    }

    @Test
    fun `listServices keeps only the service names`() {
        ServiceManager.listed = arrayOf("activity", null, 7, "qemud")

        assertEquals(listOf("activity", "qemud"), HiddenServiceManager.listServices().getOrNull())
    }
}
