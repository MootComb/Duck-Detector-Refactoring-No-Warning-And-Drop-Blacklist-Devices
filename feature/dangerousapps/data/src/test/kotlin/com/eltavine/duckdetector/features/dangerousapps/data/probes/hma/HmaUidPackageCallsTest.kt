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

package com.eltavine.duckdetector.features.dangerousapps.data.probes.hma

import org.junit.Assert.*
import org.junit.Test

class HmaUidPackageCallsTest {
    @Test fun `proxy is scan scoped and every association query reaches it`() {
        var resolved = 0
        var invoked = 0
        val binder = HmaPackageManagerBinder(resolve = { resolved++; Any() }, invoke = { _, method, args ->
            assertEquals("getPackagesForUid", method)
            assertEquals(10043, args.single())
            invoked++
            if (invoked == 1) null else arrayOf("installed.now")
        })
        assertTrue(binder.packages(10043).isEmpty())
        assertEquals(listOf("installed.now"), binder.packages(10043))
        assertEquals(1, resolved)
        assertEquals(2, invoked)
    }

    @Test fun `permission arguments follow AIDL order and result codes are strict`() {
        for ((code, granted) in listOf(0 to true, -1 to false)) {
            val binder = HmaPackageManagerBinder({ Any() }) { _, method, args ->
                assertEquals("checkUidPermission", method)
                assertEquals(listOf("permission", 10043), args.toList())
                code
            }
            assertEquals(granted, binder.permission(10043, "permission"))
        }
        for (value in listOf(null, true, 1, 0L)) {
            val binder = HmaPackageManagerBinder({ Any() }) { _, _, _ -> value }
            try { binder.permission(10043, "permission"); fail("Invalid result accepted: $value") }
            catch (_: IllegalStateException) { }
        }
    }

    @Test fun `malformed association responses are not absence`() {
        for (value in listOf(1, arrayOf<Any?>(null), arrayOf(""), arrayOf<Any?>("valid", 1))) {
            val binder = HmaPackageManagerBinder({ Any() }) { _, _, _ -> value }
            try { binder.packages(10043); fail("Invalid association accepted") }
            catch (_: IllegalStateException) { }
        }
    }
}
