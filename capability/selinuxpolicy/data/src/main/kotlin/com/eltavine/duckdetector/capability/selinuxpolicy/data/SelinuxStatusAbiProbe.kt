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

/**
 * Sends, in a forked child, the four mmap/mprotect requests that the upstream selinuxfs handler
 * sel_mmap_handle_status rejects (kernel/common security/selinux/selinuxfs.c): a two-page mapping,
 * a mapping at page offset 1, a writable private mapping and an mprotect adding PROT_WRITE to the
 * read-only baseline. A handler that dropped any of those upstream checks grants the corresponding
 * request where stock selinuxfs answers EACCES.
 *
 * The child never dereferences any mapping it obtains: on a hooked kernel a granted request can
 * describe kernel memory. Only the kernel's accept/reject decision is evidence, and the whole
 * request set runs in a disposable child so a kill lands on it, not on the app_zygote carrier.
 */
internal class SelinuxStatusAbiProbe(
    private val collector: NativeSnapshotCollector = NativeSnapshotCollector.Default,
) {

    fun inspect(): SelinuxStatusAbiSnapshot = collector.collect(
        readPayload = ::nativeProbeStatusAbi,
        parse = ::parse,
        unavailable = { status ->
            SelinuxStatusAbiSnapshot(
                attempted = false,
                state = SelinuxStatusAbiState.INCONCLUSIVE,
                failureReason = status.explain("SELinux status ABI probe was unavailable"),
            )
        },
    )

    internal fun parse(raw: String): SelinuxStatusAbiSnapshot {
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
        val reason = values["FAILURE_REASON"]?.let(NativePayloadCodec::decodeValue)
        // An outcome this build does not know is treated as unknown.
        return when (Outcome.entries.firstOrNull { it.name == values["OUTCOME"] }) {
            Outcome.VIOLATION -> SelinuxStatusAbiSnapshot(
                attempted = attempted,
                state = SelinuxStatusAbiState.VIOLATION,
                violatedRequests = parseViolated(values["VIOLATED"]),
                pageSize = values["PAGE_SIZE"]?.toLongOrNull(),
                failureReason = reason,
                notes = notes,
            )

            Outcome.NO_VIOLATION -> SelinuxStatusAbiSnapshot(
                attempted = attempted,
                state = SelinuxStatusAbiState.NO_VIOLATION,
                pageSize = values["PAGE_SIZE"]?.toLongOrNull(),
                failureReason = reason,
                notes = notes,
            )

            Outcome.UNAVAILABLE -> SelinuxStatusAbiSnapshot(
                attempted = attempted,
                state = SelinuxStatusAbiState.UNAVAILABLE,
                pageSize = values["PAGE_SIZE"]?.toLongOrNull(),
                failureReason = reason ?: UNREPORTED_REASON,
                notes = notes,
            )

            Outcome.INCONCLUSIVE, null -> SelinuxStatusAbiSnapshot(
                attempted = attempted,
                state = SelinuxStatusAbiState.INCONCLUSIVE,
                pageSize = values["PAGE_SIZE"]?.toLongOrNull(),
                failureReason = reason ?: UNREPORTED_REASON,
                notes = notes,
            )
        }
    }

    private fun parseViolated(raw: String?): List<SelinuxStatusAbiRequestKind> {
        if (raw.isNullOrBlank()) {
            return emptyList()
        }
        return raw.split(',')
            .mapNotNull { name -> SelinuxStatusAbiRequestKind.entries.firstOrNull { it.name == name.trim() } }
    }

    private external fun nativeProbeStatusAbi(): String

    /** The outcome names selinux_status_abi_native_bridge.cpp writes. */
    private enum class Outcome {
        VIOLATION,
        NO_VIOLATION,
        UNAVAILABLE,
        INCONCLUSIVE,
    }

    private companion object {
        const val UNREPORTED_REASON = "The status ABI probe did not report a reason."
    }
}
