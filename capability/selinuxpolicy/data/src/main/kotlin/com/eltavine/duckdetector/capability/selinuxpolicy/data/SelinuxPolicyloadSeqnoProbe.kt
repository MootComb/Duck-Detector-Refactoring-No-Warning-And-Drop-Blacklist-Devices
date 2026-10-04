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

import com.eltavine.duckdetector.core.platform.PlatformFailureName
import java.io.FileInputStream
import java.io.IOException
import java.io.RandomAccessFile

// States are only appended, so every existing state keeps its ordinal.
public enum class SelinuxPolicyloadSeqnoState {
    CLEAN,
    SUSPICIOUS,
    INCONCLUSIVE,
    UNAVAILABLE,

    /** Reading the status page this oracle compares killed a disposable child; stock selinuxfs never does. */
    STATUS_PAGE_FAULTED,
}

public data class SelinuxPolicyloadSeqnoResult(
    val state: SelinuxPolicyloadSeqnoState,
    val available: Boolean,
    val probeAttempted: Boolean,
    val statusSequence: Long? = null,
    val statusPolicyload: Long? = null,
    val accessSeqno: Long? = null,
    val processClass: Int? = null,
    val failureReason: String? = null,
    val notes: List<String> = emptyList(),
)

public class SelinuxPolicyloadSeqnoProbe {

    /**
     * Compares the status page's policyload counter with the access oracle's sequence number.
     *
     * The status page comes from the disposable child behind [statusPage]; this process never reads
     * it. On a kernel whose hook breaks the node, a read() here would make selinuxfs dereference a
     * bogus page pointer in kernel mode (kernel/common security/selinux/selinuxfs.c,
     * sel_read_handle_status), and mapping it would kill this carrier the way it killed the child.
     */
    internal fun inspect(
        statusPage: SelinuxStatusPageResult,
        queryAccess: () -> AccessDecision = ::queryAccessDecision,
    ): SelinuxPolicyloadSeqnoResult = when (statusPage) {
        is SelinuxStatusPageResult.Intact -> runCatching { interpret(statusPage.header, queryAccess()) }
            .getOrElse { throwable ->
                SelinuxPolicyloadSeqnoResult(
                    state = SelinuxPolicyloadSeqnoState.UNAVAILABLE,
                    available = false,
                    probeAttempted = true,
                    failureReason = throwable.message ?: PlatformFailureName.of(throwable),
                    notes = listOf(ZYGOTE_PRELOAD_NOTE),
                )
            }

        is SelinuxStatusPageResult.Faulted -> SelinuxPolicyloadSeqnoResult(
            state = SelinuxPolicyloadSeqnoState.STATUS_PAGE_FAULTED,
            available = true,
            probeAttempted = true,
            notes = statusPage.notes + ZYGOTE_PRELOAD_NOTE,
        )

        is SelinuxStatusPageResult.Unavailable -> unreadStatusPage(statusPage, statusPage.reason)
        is SelinuxStatusPageResult.Inconclusive -> unreadStatusPage(statusPage, statusPage.reason)
    }

    private fun unreadStatusPage(
        statusPage: SelinuxStatusPageResult,
        reason: String,
    ): SelinuxPolicyloadSeqnoResult = SelinuxPolicyloadSeqnoResult(
        state = SelinuxPolicyloadSeqnoState.UNAVAILABLE,
        available = false,
        probeAttempted = statusPage.attempted,
        failureReason = reason,
        notes = statusPage.notes + ZYGOTE_PRELOAD_NOTE,
    )

    internal fun interpret(
        status: SelinuxStatusHeader,
        access: AccessDecision,
    ): SelinuxPolicyloadSeqnoResult {
        val state = when {
            status.sequence % 2L != 0L -> SelinuxPolicyloadSeqnoState.INCONCLUSIVE

            status.policyload > 0L && access.seqno > 0L && status.policyload == access.seqno ->
                SelinuxPolicyloadSeqnoState.CLEAN

            status.sequence > 0L && status.policyload == 0L && access.seqno > 0L ->
                SelinuxPolicyloadSeqnoState.SUSPICIOUS

            status.policyload > 0L && access.seqno > 0L && status.policyload != access.seqno ->
                SelinuxPolicyloadSeqnoState.SUSPICIOUS

            else -> SelinuxPolicyloadSeqnoState.INCONCLUSIVE
        }
        return SelinuxPolicyloadSeqnoResult(
            state = state,
            available = true,
            probeAttempted = true,
            statusSequence = status.sequence,
            statusPolicyload = status.policyload,
            accessSeqno = access.seqno,
            processClass = access.processClass,
            notes = listOf(ZYGOTE_PRELOAD_NOTE),
        )
    }

    private fun queryAccessDecision(): AccessDecision {
        val processClass = readProcessClass()
        val query = "$APP_ZYGOTE_CONTEXT $ISOLATED_APP_CONTEXT $processClass"
        RandomAccessFile(SELINUX_ACCESS, "rw").use { file ->
            file.write(query.toByteArray(Charsets.US_ASCII))
            file.seek(0L)
            val buffer = ByteArray(ACCESS_RESPONSE_MAX_BYTES)
            val count = file.read(buffer)
            if (count <= 0) {
                throw IOException("SELinux access response was empty.")
            }
            val fields = String(buffer, 0, count, Charsets.US_ASCII).trim().split(Regex("\\s+"))
            if (fields.size < 6) {
                throw IOException("SELinux access response had ${fields.size} fields.")
            }
            return AccessDecision(
                processClass = processClass,
                seqno = fields[4].toLongOrNull()
                    ?: throw IOException("SELinux access seqno was not numeric."),
            )
        }
    }

    private fun readProcessClass(): Int {
        return FileInputStream(SELINUX_PROCESS_CLASS).use { input ->
            input.bufferedReader().readText().trim().toIntOrNull()
        } ?: throw IOException("SELinux process class was unreadable.")
    }

    internal data class AccessDecision(
        val processClass: Int,
        val seqno: Long,
    )

    public companion object {
        private const val SELINUX_ACCESS = "/sys/fs/selinux/access"
        private const val SELINUX_PROCESS_CLASS = "/sys/fs/selinux/class/process/index"
        private const val APP_ZYGOTE_CONTEXT = "u:r:app_zygote:s0"
        private const val ISOLATED_APP_CONTEXT = "u:r:isolated_app:s0"
        private const val ACCESS_RESPONSE_MAX_BYTES = 256
        private const val ZYGOTE_PRELOAD_NOTE =
            "This oracle is trusted only when produced by android:zygotePreloadName inside the dedicated app_zygote carrier."
    }
}
