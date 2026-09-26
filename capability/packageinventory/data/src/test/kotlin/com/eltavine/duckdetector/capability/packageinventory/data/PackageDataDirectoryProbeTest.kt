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

package com.eltavine.duckdetector.capability.packageinventory.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PackageDataDirectoryProbeTest {

    private val probe = PackageDataDirectoryProbe()

    @Test
    fun `no packages to check is an answered empty set`() {
        assertEquals(emptySet<String>(), probe.statPackages(emptyList()))
    }

    @Test
    fun `a native library that did not load gives no answer rather than no packages`() {
        // JVM unit tests never load libduckdetector, which is the unavailable case on a device.
        assertNull(probe.statPackages(listOf("com.example.target")))
    }
}
