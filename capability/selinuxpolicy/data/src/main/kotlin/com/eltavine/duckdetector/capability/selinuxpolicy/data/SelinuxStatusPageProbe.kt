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

import com.eltavine.duckdetector.core.native.NativePayloadCodec
import com.eltavine.duckdetector.core.native.NativePayloadContract
import com.eltavine.duckdetector.core.native.NativeSnapshotCollector

/** struct selinux_kernel_status, as the status page holds it. */
internal data class SelinuxStatusHeader(
    val version: Long,
    val sequence: Long,
    val enforcing: Long,
    val policyload: Long,
    val denyUnknown: Long,
)

/** What a disposable child of this process saw when it opened, mapped and read /sys/fs/selinux/status. */
internal sealed interface SelinuxStatusPageResult {

    /** Whether a child was forked to read the page. */
    val attempted: Boolean

    val notes: List<String>

    /**
     * Why this process must not let libselinux map and read the page, or null when it may. The first
     * android.os.SELinux.checkSELinuxAccess does exactly that, so only a page that read back intact, or
     * one libselinux cannot map either and so never reads, is safe.
     */
    val accessCheckBlockReason: String?
        get() = when (this) {
            is Intact, is Unavailable -> null
            is Faulted ->
                "Skipped: reading /sys/fs/selinux/status killed a disposable child" +
                    signal?.let { " (signal $it)" }.orEmpty() +
                    ", and libselinux reads it on the first access check."

            is Inconclusive ->
                "Skipped: the status page probe was inconclusive ($reason), " +
                    "so libselinux was not allowed to read /sys/fs/selinux/status."
        }

    /** The page read back like stock selinuxfs. */
    data class Intact(
        val header: SelinuxStatusHeader,
        override val notes: List<String> = emptyList(),
    ) : SelinuxStatusPageResult {
        override val attempted: Boolean get() = true
    }

    /** The child mapped the page, and a signal ended it before it read the header back. */
    data class Faulted(
        val signal: Int?,
        override val notes: List<String> = emptyList(),
    ) : SelinuxStatusPageResult {
        override val attempted: Boolean get() = true
    }

    /** open or mmap failed, so libselinux falls back to netlink and never reads a mapping. */
    data class Unavailable(
        val reason: String,
        override val notes: List<String> = emptyList(),
    ) : SelinuxStatusPageResult {
        override val attempted: Boolean get() = true
    }

    /** The child could not run, ended before it mapped the page, or did not report. */
    data class Inconclusive(
        val reason: String,
        override val attempted: Boolean,
        override val notes: List<String> = emptyList(),
    ) : SelinuxStatusPageResult
}

/**
 * Reproduces, in a forked child, the access libselinux makes to the SELinux status page on its first
 * access check (external/selinux libselinux/src/sestatus.c, selinux_status_open): open, mmap, read.
 *
 * A kernel hook that breaks the node's open handler makes that read fault, and the kernel kills the
 * reader. Doing the read in a child turns that kill into a result instead of losing the app_zygote
 * carrier, and tells the carrier whether its own access checks would be killed the same way.
 */
internal class SelinuxStatusPageProbe(
    private val collector: NativeSnapshotCollector = NativeSnapshotCollector.Default,
) {

    fun inspect(): SelinuxStatusPageResult = collector.collect(
        readPayload = ::nativeProbeStatusPage,
        parse = ::parse,
        unavailable = { status ->
            SelinuxStatusPageResult.Inconclusive(
                reason = status.explain("SELinux status page probe was unavailable"),
                attempted = false,
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

        val attempted = NativePayloadCodec.decodeFlag(values["ATTEMPTED"])
        val reason = values["FAILURE_REASON"]?.let(NativePayloadCodec::decodeValue) ?: UNREPORTED_REASON
        // An outcome this build does not know is treated as unknown, which keeps libselinux off the page.
        return when (Outcome.entries.firstOrNull { it.name == values["OUTCOME"] }) {
            Outcome.INTACT -> parseHeader(values)?.let { header -> SelinuxStatusPageResult.Intact(header, notes) }
                ?: SelinuxStatusPageResult.Inconclusive(INCOMPLETE_HEADER_REASON, attempted, notes)

            Outcome.FAULTED -> SelinuxStatusPageResult.Faulted(values["SIGNAL"]?.toIntOrNull(), notes)
            Outcome.UNAVAILABLE -> SelinuxStatusPageResult.Unavailable(reason, notes)
            Outcome.INCONCLUSIVE, null -> SelinuxStatusPageResult.Inconclusive(reason, attempted, notes)
        }
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

    /** The outcome names selinux_status_page_native_bridge.cpp writes. */
    private enum class Outcome {
        INTACT,
        FAULTED,
        UNAVAILABLE,
        INCONCLUSIVE,
    }

    private companion object {
        const val INCOMPLETE_HEADER_REASON = "Status page read back without a complete header."
        const val UNREPORTED_REASON = "The status page probe did not report a reason."
    }
}
