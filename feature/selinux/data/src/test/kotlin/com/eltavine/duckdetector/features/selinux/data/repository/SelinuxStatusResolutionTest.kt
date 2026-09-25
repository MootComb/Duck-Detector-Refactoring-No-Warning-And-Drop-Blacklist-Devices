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

package com.eltavine.duckdetector.features.selinux.data.repository

import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxStatusResolutionTest {

    @Test
    fun `a readable permissive enforce node wins over every other probe`() {
        val resolution = determineStatusWithParadoxLogic(
            listOf(filesystem(FILESYSTEM_ACTIVE), result("sysfs", "Permissive"), result("getenforce", "Enforcing")),
        )

        assertEquals(SelinuxMode.PERMISSIVE, resolution.mode)
    }

    @Test
    fun `a missing selinuxfs reads as disabled`() {
        assertEquals(SelinuxMode.DISABLED, determineStatusWithParadoxLogic(listOf(filesystem(FILESYSTEM_NOT_MOUNTED))).mode)
    }

    @Test
    fun `a denied read of the enforce node proves enforcing`() {
        val resolution = determineStatusWithParadoxLogic(
            listOf(filesystem(FILESYSTEM_ACTIVE), result("sysfs", "Blocked (Enforcing)", permissionDenied = true)),
        )

        assertEquals(SelinuxMode.ENFORCING, resolution.mode)
        assertTrue(resolution.paradoxDetected)
    }

    @Test
    fun `a denied process attribute read proves nothing about the mode`() {
        val resolution = determineStatusWithParadoxLogic(
            listOf(filesystem(FILESYSTEM_ACTIVE), result("proc/self/attr", "Not readable", permissionDenied = true)),
        )

        assertEquals(SelinuxMode.UNKNOWN, resolution.mode)
    }

    @Test
    fun `an unobserved mode stays unknown instead of defaulting to enforcing`() {
        val resolution = determineStatusWithParadoxLogic(
            listOf(filesystem(FILESYSTEM_ACTIVE), result("sysfs", "Error"), result("getenforce", "No output")),
        )

        assertEquals(SelinuxMode.UNKNOWN, resolution.mode)
        assertFalse(resolution.paradoxDetected)
    }

    @Test
    fun `an app context shows the domain but never the enforcing mode`() {
        val result = classifyProcAttrContext("u:r:untrusted_app:s0:c12,c257,c512,c768\u0000")

        assertEquals(PROC_ATTR_LABELED, result.status)
        assertNull(result.isSecure)
        assertEquals(
            SelinuxMode.UNKNOWN,
            determineStatusWithParadoxLogic(listOf(filesystem(FILESYSTEM_ACTIVE), result)).mode,
        )
    }

    @Test
    fun `an app process in the kernel or init domain is unexpected`() {
        listOf("u:r:kernel:s0", "u:r:init:s0").forEach { context ->
            val result = classifyProcAttrContext(context)

            assertEquals(context, "Unexpected context", result.status)
            assertEquals(context, false, result.isSecure)
        }
    }

    private fun filesystem(status: String) = result("filesystem", status)

    private fun result(method: String, status: String, permissionDenied: Boolean = false) =
        SelinuxCheckResult(method = method, status = status, isSecure = null, permissionDenied = permissionDenied)
}
