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

import com.eltavine.duckdetector.core.native.NativePayloadCodec
import com.eltavine.duckdetector.core.native.NativePayloadContract
import com.eltavine.duckdetector.core.native.NativeSnapshotCollector

/** What a disposable child of this process saw when it opened, mapped and read /sys/fs/selinux/status. */
internal enum class SelinuxStatusPageState {
    /** The page read back like stock selinuxfs. */
    INTACT,

    /** A signal killed the child on the first read of the mapping. */
    HOSTILE,

    /** open or mmap failed, so libselinux falls back to netlink and never reads a mapping. */
    UNAVAILABLE,

    /** The child could not run or did not report, so whether the read faults is unknown. */
    INCONCLUSIVE,
}

/** struct selinux_kernel_status, as the status page holds it. */
internal data class SelinuxStatusHeader(
    val version: Long,
    val sequence: Long,
    val enforcing: Long,
    val policyload: Long,
    val denyUnknown: Long,
)

internal data class SelinuxStatusPageResult(
    val state: SelinuxStatusPageState,
    val attempted: Boolean = false,
    val terminatingSignal: Int? = null,
    /** The header the child read, present only when [state] is [SelinuxStatusPageState.INTACT]. */
    val header: SelinuxStatusHeader? = null,
    val failureReason: String? = null,
    val notes: List<String> = emptyList(),
) {
    /**
     * Whether this process may let libselinux map and read the page itself. The first
     * android.os.SELinux.checkSELinuxAccess does exactly that, so only a page that read back intact,
     * or one libselinux cannot map either, is safe; a hostile or unknown page is not.
     */
    val allowsInProcessAccess: Boolean
        get() = state == SelinuxStatusPageState.INTACT || state == SelinuxStatusPageState.UNAVAILABLE

    /** Why access checks that would make libselinux read the page were skipped, or null if they may run. */
    val skipReason: String?
        get() = when (state) {
            SelinuxStatusPageState.INTACT, SelinuxStatusPageState.UNAVAILABLE -> null
            SelinuxStatusPageState.HOSTILE ->
                "Skipped: reading /sys/fs/selinux/status killed a disposable child" +
                    (terminatingSignal?.let { " (signal $it)" } ?: "") +
                    ", and libselinux reads it on the first access check."

            SelinuxStatusPageState.INCONCLUSIVE ->
                "Skipped: the status page probe was inconclusive" +
                    (failureReason?.let { " ($it)" } ?: "") +
                    ", so libselinux was not allowed to read /sys/fs/selinux/status."
        }
}

/**
 * Reproduces, in a forked child, the access libselinux makes to the SELinux status page on its first
 * access check (external/selinux libselinux/src/sestatus.c, selinux_status_open): open, mmap, read.
 *
 * A kernel hook that breaks the node's open handler makes that read fault, and the kernel kills the
 * reader. Doing the read in a child turns that kill into a result instead of losing the app_zygote
 * carrier, and tells the carrier whether its own access checks would be killed the same way.
 */
internal open class SelinuxStatusPageProbe(
    private val collector: NativeSnapshotCollector = NativeSnapshotCollector.Default,
) {

    open fun inspect(): SelinuxStatusPageResult = collector.collect(
        readPayload = ::nativeProbeStatusPage,
        parse = ::parse,
        unavailable = { status ->
            SelinuxStatusPageResult(
                state = SelinuxStatusPageState.INCONCLUSIVE,
                failureReason = status.explain("SELinux status page probe was unavailable"),
            )
        },
    )

    internal fun parse(raw: String): SelinuxStatusPageResult {
        NativePayloadContract.requireKeys(raw, "OUTCOME")
        val values = mutableMapOf<String, String>()
        val notes = mutableListOf<String>()
        raw.lineSequence()
            .map { it.trim() }
            .filter { it.contains('=') }
            .forEach { line ->
                val key = line.substringBefore('=')
                val value = line.substringAfter('=')
                if (key == "NOTE") {
                    notes += NativePayloadCodec.decodeValue(value)
                } else {
                    values[key] = value
                }
            }

        // An outcome this build does not know is treated as unknown, which keeps libselinux off the page.
        val reportedState = SelinuxStatusPageState.entries.firstOrNull { it.name == values["OUTCOME"] }
            ?: SelinuxStatusPageState.INCONCLUSIVE
        val header = if (reportedState == SelinuxStatusPageState.INTACT) parseHeader(values) else null
        val incompleteRead = reportedState == SelinuxStatusPageState.INTACT && header == null
        return SelinuxStatusPageResult(
            state = if (incompleteRead) SelinuxStatusPageState.INCONCLUSIVE else reportedState,
            attempted = NativePayloadCodec.decodeFlag(values["ATTEMPTED"]),
            terminatingSignal = values["SIGNAL"]?.toIntOrNull(),
            header = header,
            failureReason = values["FAILURE_REASON"]?.let(NativePayloadCodec::decodeValue)
                ?: "Status page read back without a complete header.".takeIf { incompleteRead },
            notes = notes,
        )
    }

    private fun parseHeader(values: Map<String, String>): SelinuxStatusHeader? {
        return SelinuxStatusHeader(
            version = values["VERSION"]?.toLongOrNull() ?: return null,
            sequence = values["SEQUENCE"]?.toLongOrNull() ?: return null,
            enforcing = values["ENFORCING"]?.toLongOrNull() ?: return null,
            policyload = values["POLICYLOAD"]?.toLongOrNull() ?: return null,
            denyUnknown = values["DENY_UNKNOWN"]?.toLongOrNull() ?: return null,
        )
    }

    private external fun nativeProbeStatusPage(): String
}
