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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxStatusAbiProbeTest {

    private val probe = SelinuxStatusAbiProbe()

    @Test
    fun `actual native violation payload survives carrier encoding`() {
        val raw = requireNotNull(javaClass.getResource("/selinux-status-abi-violation.txt")).readText()
        // test_status_abi_native.py compares this fixture to the actual JNI encoder output.
        val result = probe.parse(raw)
        assertEquals(SelinuxStatusAbiState.VIOLATION, result.state)
        assertEquals(SelinuxStatusAbiRequestKind.entries, result.violatedRequests)
        val carrier = SelinuxContextValiditySnapshot(statusAbi = result)
        assertEquals(
            result,
            SelinuxContextValidityBridge().parse(SelinuxContextValidityPayloadCodec.encode(carrier)).statusAbi,
        )
    }

    @Test
    fun `actual partial native violation survives timeout and later preload failure`() {
        val raw = requireNotNull(javaClass.getResource("/selinux-status-abi-partial.txt")).readText()
        val result = probe.parse(raw)
        assertEquals(SelinuxStatusAbiState.VIOLATION, result.state)
        assertEquals(listOf(SelinuxStatusAbiRequestKind.TWO_PAGE_SHARED), result.violatedRequests)
        assertEquals("Status ABI child did not finish within 1000 ms and was stopped.", result.failureReason)
        assertEquals(3, result.notes.count { it.endsWith("has no reported outcome.") })
        assertTrue(result.attempted)
        val carrier = SelinuxContextValiditySnapshot(statusAbi = result)
        assertEquals(
            result,
            SelinuxContextValidityBridge().parse(SelinuxContextValidityPayloadCodec.encode(carrier)).statusAbi,
        )
        assertEquals(
            result,
            SelinuxContextValidityBridge().parse(
                SelinuxContextValidityPreload().fallbackPayload("later preload failure", statusAbi = result),
            ).statusAbi,
        )
    }

    @Test
    fun `a violation names the granted requests`() {
        val result = probe.parse(
            """
            ATTEMPTED=1
            OUTCOME=VIOLATION
            VIOLATED=TWO_PAGE_SHARED,MPROTECT_WRITE
            PAGE_SIZE=4096
            NOTE=Request TWO_PAGE_SHARED was granted on the status node.
            NOTE=Request MPROTECT_WRITE was granted on the status node.
            """.trimIndent(),
        )

        assertEquals(SelinuxStatusAbiState.VIOLATION, result.state)
        assertEquals(
            listOf(SelinuxStatusAbiRequestKind.TWO_PAGE_SHARED, SelinuxStatusAbiRequestKind.MPROTECT_WRITE),
            result.violatedRequests,
        )
        assertEquals(4096L, result.pageSize)
        assertTrue(result.attempted)
        assertEquals(2, result.notes.size)
    }

    @Test
    fun `a clean run keeps no violated requests`() {
        val result = probe.parse(
            """
            ATTEMPTED=1
            OUTCOME=NO_VIOLATION
            PAGE_SIZE=16384
            NOTE=Request TWO_PAGE_SHARED was rejected (errno=13).
            NOTE=Every nonconforming request was rejected like stock selinuxfs does.
            """.trimIndent(),
        )

        assertEquals(SelinuxStatusAbiState.NO_VIOLATION, result.state)
        assertEquals(emptyList<SelinuxStatusAbiRequestKind>(), result.violatedRequests)
        assertEquals(16384L, result.pageSize)
    }

    @Test
    fun `an unavailable node carries its reason`() {
        val result = probe.parse(
            """
            ATTEMPTED=1
            OUTCOME=UNAVAILABLE
            FAILURE_REASON=open of /sys/fs/selinux/status failed (errno=13).
            """.trimIndent(),
        )

        assertEquals(SelinuxStatusAbiState.UNAVAILABLE, result.state)
        assertEquals("open of /sys/fs/selinux/status failed (errno=13).", result.failureReason)
    }

    @Test
    fun `an inconclusive run keeps the attempt flag`() {
        val result = probe.parse(
            """
            ATTEMPTED=1
            OUTCOME=INCONCLUSIVE
            FAILURE_REASON=Status ABI child was killed by SIGSEGV before it finished the request set.
            """.trimIndent(),
        )

        assertEquals(SelinuxStatusAbiState.INCONCLUSIVE, result.state)
        assertTrue(result.attempted)
    }

    @Test
    fun `an outcome this build does not know reads as inconclusive`() {
        val result = probe.parse("ATTEMPTED=1\nOUTCOME=SOMETHING_NEW\n")

        assertEquals(SelinuxStatusAbiState.INCONCLUSIVE, result.state)
    }

    @Test
    fun `violated requests this build does not know are dropped`() {
        val result = probe.parse("ATTEMPTED=1\nOUTCOME=VIOLATION\nVIOLATED=TWO_PAGE_SHARED,FUTURE_REQUEST\n")

        assertEquals(
            listOf(SelinuxStatusAbiRequestKind.TWO_PAGE_SHARED),
            result.violatedRequests,
        )
    }

    @Test
    fun `an escaped failure reason decodes`() {
        val result = probe.parse(
            "ATTEMPTED=0\nOUTCOME=INCONCLUSIVE\nFAILURE_REASON=reason with\\nnewline",
        )

        assertEquals("reason with\nnewline", result.failureReason)
    }
}
