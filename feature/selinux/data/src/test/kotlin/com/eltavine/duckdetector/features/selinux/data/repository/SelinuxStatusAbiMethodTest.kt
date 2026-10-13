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

package com.eltavine.duckdetector.features.selinux.data.repository

import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxStatusAbiRequestKind
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxStatusAbiSnapshot
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxStatusAbiState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStatusAbiRequest
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStatusAbiVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxStatusAbiMethodTest {

    @Test
    fun `a partial violation retains evidence and explains unfinished requests`() {
        val result = buildStatusAbiMethod(
            SelinuxStatusAbiSnapshot(
                attempted = true,
                state = SelinuxStatusAbiState.VIOLATION,
                violatedRequests = listOf(SelinuxStatusAbiRequestKind.TWO_PAGE_SHARED),
                failureReason = "Status ABI child did not finish within 1000 ms and was stopped.",
                notes = listOf("Request OFFSET_SHARED has no reported outcome."),
            ),
        )
        assertEquals(false, result.isSecure)
        assertEquals(SelinuxStatusAbiVerdict.ABI_VIOLATION, result.statusAbi?.verdict)
        assertEquals(listOf(SelinuxStatusAbiRequest.TWO_PAGE_SHARED), result.statusAbi?.violatedRequests)
        assertEquals(listOf("Request OFFSET_SHARED has no reported outcome."), result.statusAbi?.notes)
        assertTrue(result.details.orEmpty().contains("2-page shared mmap"))
        assertTrue(result.details.orEmpty().contains("The request set did not finish"))
        assertTrue(result.details.orEmpty().contains("1000 ms"))
    }

    @Test
    fun `a violation reads as insecure and lists the granted requests`() {
        val result = buildStatusAbiMethod(
            SelinuxStatusAbiSnapshot(
                attempted = true,
                state = SelinuxStatusAbiState.VIOLATION,
                violatedRequests = listOf(
                    SelinuxStatusAbiRequestKind.TWO_PAGE_SHARED,
                    SelinuxStatusAbiRequestKind.WRITABLE_PRIVATE,
                    SelinuxStatusAbiRequestKind.MPROTECT_WRITE,
                ),
                pageSize = 4096,
                notes = listOf("Request TWO_PAGE_SHARED was granted on the status node."),
            ),
        )

        assertEquals(SelinuxOracle.STATUS_MMAP_ABI.label, result.method)
        assertEquals(SelinuxStatusAbiVerdict.ABI_VIOLATION, result.statusAbi?.verdict)
        assertEquals(false, result.isSecure)
        assertEquals(
            listOf(
                SelinuxStatusAbiRequest.TWO_PAGE_SHARED,
                SelinuxStatusAbiRequest.WRITABLE_PRIVATE,
                SelinuxStatusAbiRequest.MPROTECT_WRITE,
            ),
            result.statusAbi?.violatedRequests,
        )
        assertTrue(result.details.orEmpty().contains("2-page shared mmap"))
    }

    @Test
    fun `a clean run never reads as secure`() {
        val result = buildStatusAbiMethod(
            SelinuxStatusAbiSnapshot(
                attempted = true,
                state = SelinuxStatusAbiState.NO_VIOLATION,
                pageSize = 4096,
            ),
        )

        assertNull(result.isSecure)
        assertEquals(SelinuxStatusAbiVerdict.NO_VIOLATION, result.statusAbi?.verdict)
        assertTrue(
            result.details.orEmpty().contains("A handler that keeps the upstream checks answers the same way"),
        )
    }

    @Test
    fun `unavailable carries the failure reason as details`() {
        val result = buildStatusAbiMethod(
            SelinuxStatusAbiSnapshot(
                attempted = true,
                state = SelinuxStatusAbiState.UNAVAILABLE,
                failureReason = "open of /sys/fs/selinux/status failed (errno=13).",
            ),
        )

        assertNull(result.isSecure)
        assertEquals("open of /sys/fs/selinux/status failed (errno=13).", result.details)
    }

    @Test
    fun `an empty snapshot reads as inconclusive`() {
        val result = buildStatusAbiMethod(SelinuxStatusAbiSnapshot())

        assertNull(result.isSecure)
        assertEquals(SelinuxStatusAbiVerdict.INCONCLUSIVE, result.statusAbi?.verdict)
    }
}
