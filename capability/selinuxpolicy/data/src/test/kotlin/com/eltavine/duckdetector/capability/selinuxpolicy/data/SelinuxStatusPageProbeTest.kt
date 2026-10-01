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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

import com.eltavine.duckdetector.core.native.NativeLibraryHandle
import com.eltavine.duckdetector.core.native.NativeSnapshotCollector
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxStatusPageProbeTest {

    private val probe = SelinuxStatusPageProbe()

    @Test
    fun `an intact page carries its header and lets libselinux read it`() {
        val result = probe.parse(
            """
            ATTEMPTED=1
            OUTCOME=INTACT
            VERSION=1
            SEQUENCE=4
            ENFORCING=1
            POLICYLOAD=2
            DENY_UNKNOWN=0
            NOTE=Status page read back: version=1 sequence=4 enforcing=1 policyload=2 deny_unknown=0.
            """.trimIndent(),
        )

        assertEquals(SelinuxStatusPageState.INTACT, result.state)
        assertTrue(result.attempted)
        assertEquals(SelinuxStatusHeader(1, 4, 1, 2, 0), result.header)
        assertTrue(result.allowsInProcessAccess)
        assertNull(result.skipReason)
        assertEquals(1, result.notes.size)
    }

    @Test
    fun `a page that killed the child keeps libselinux off it and names the signal`() {
        val result = probe.parse(
            """
            ATTEMPTED=1
            OUTCOME=HOSTILE
            SIGNAL=9
            NOTE=Child opened and mapped /sys/fs/selinux/status, then was killed by SIGKILL on the first read of the mapping.
            """.trimIndent(),
        )

        assertEquals(SelinuxStatusPageState.HOSTILE, result.state)
        assertEquals(9, result.terminatingSignal)
        assertNull(result.header)
        assertFalse(result.allowsInProcessAccess)
        assertTrue(result.skipReason.orEmpty().contains("signal 9"))
    }

    @Test
    fun `a page libselinux cannot map either stays safe for its access checks`() {
        val result = probe.parse(
            """
            ATTEMPTED=1
            OUTCOME=UNAVAILABLE
            FAILURE_REASON=open of /sys/fs/selinux/status failed (errno=13).
            """.trimIndent(),
        )

        assertEquals(SelinuxStatusPageState.UNAVAILABLE, result.state)
        assertTrue(result.allowsInProcessAccess)
        assertNull(result.skipReason)
        assertEquals("open of /sys/fs/selinux/status failed (errno=13).", result.failureReason)
    }

    @Test
    fun `an inconclusive probe keeps libselinux off the page and explains why`() {
        val result = probe.parse(
            """
            ATTEMPTED=1
            OUTCOME=INCONCLUSIVE
            FAILURE_REASON=Status page child did not finish within 1000 ms\nand was stopped.
            """.trimIndent(),
        )

        assertEquals(SelinuxStatusPageState.INCONCLUSIVE, result.state)
        assertEquals("Status page child did not finish within 1000 ms\nand was stopped.", result.failureReason)
        assertFalse(result.allowsInProcessAccess)
        assertTrue(result.skipReason.orEmpty().contains("inconclusive"))
    }

    @Test
    fun `an intact report without a full header is not trusted`() {
        val result = probe.parse(
            """
            ATTEMPTED=1
            OUTCOME=INTACT
            VERSION=1
            SEQUENCE=4
            """.trimIndent(),
        )

        assertEquals(SelinuxStatusPageState.INCONCLUSIVE, result.state)
        assertNull(result.header)
        assertFalse(result.allowsInProcessAccess)
        assertEquals("Status page read back without a complete header.", result.failureReason)
    }

    @Test
    fun `an outcome this build does not know fails safe`() {
        val result = probe.parse("ATTEMPTED=1\nOUTCOME=SOMETHING_NEW\n")

        assertEquals(SelinuxStatusPageState.INCONCLUSIVE, result.state)
        assertFalse(result.allowsInProcessAccess)
    }

    @Test
    fun `an unloaded native library leaves the page untouched`() {
        val unloaded = SelinuxStatusPageProbe(
            collector = NativeSnapshotCollector(
                library = object : NativeLibraryHandle {
                    override val isLoaded: Boolean = false
                    override val loadFailureDetail: String = "dlopen failed"
                },
            ),
        )

        val result = unloaded.inspect()

        assertEquals(SelinuxStatusPageState.INCONCLUSIVE, result.state)
        assertFalse(result.attempted)
        assertFalse(result.allowsInProcessAccess)
        assertTrue(result.failureReason.orEmpty().contains("dlopen failed"))
    }
}
