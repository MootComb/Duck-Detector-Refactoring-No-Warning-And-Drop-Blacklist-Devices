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

package com.eltavine.duckdetector.features.nativeroot.data.service

import com.eltavine.duckdetector.core.native.NativeCollectionOutcome
import com.eltavine.duckdetector.core.native.NativeCollectionStatus
import com.eltavine.duckdetector.core.native.NativePayloadCodec
import com.eltavine.duckdetector.core.native.NativePayloadContract

data class ThroneHuntCarrierState(
    val collection: NativeCollectionStatus = NativeCollectionStatus.Collected,
    val watchInstalled: Boolean = false,
    val watchDescriptor: Int = -1,
    val packageDirectory: String = "",
    val failureReason: String? = null,
    val notes: List<String> = emptyList(),
    val directoryOpenCount: Int = 0,
    val directoryAccessCount: Int = 0,
    val rawEventCount: Int = 0,
    val invalidEventCount: Int = 0,
) {
    // A denied watch never counts as coverage: the carrier reports it as a failure reason whose
    // text carries "denied", and the round must surface that instead of a clean zero.
    val watchDenied: Boolean
        get() = failureReason?.contains("denied", ignoreCase = true) == true
}

// The preload carrier hands the isolated child a plain string because the watch descriptor is
// inherited through fork, not through the Binder transaction. Keeping the encoding trivial means
// the isolated child can rebuild the state with no framework dependency.
object ThroneHuntCarrierPayloadCodec {

    // The codec intentionally delegates all escaping to the shared cross-process table; the watch
    // descriptor is inherited through fork, so this is a local Binder envelope, not a native payload.
    // 所有转义都委托到共享跨进程表；watch 描述符通过 fork 继承，所以这里是本地 Binder 信封而不是原生 payload。

    fun encode(state: ThroneHuntCarrierState): String {
        return buildString {
            append("NATIVE_COLLECTION_OUTCOME=")
            append(state.collection.outcome.name)
            append('\n')
            append("NATIVE_COLLECTION_DETAIL=")
            append(NativePayloadCodec.encodeValue(state.collection.detail))
            append('\n')
            append("WATCH_INSTALLED=")
            append(if (state.watchInstalled) '1' else '0')
            append('\n')
            append("WATCH_DESCRIPTOR=")
            append(state.watchDescriptor)
            append('\n')
            append("WATCH_PACKAGE_DIR=")
            append(NativePayloadCodec.encodeValue(state.packageDirectory))
            append('\n')
            if (state.failureReason != null) {
                append("FAILURE_REASON=")
                append(NativePayloadCodec.encodeValue(state.failureReason))
                append('\n')
            }
            append("EVENT_DIRECTORY_OPEN=")
            append(state.directoryOpenCount)
            append('\n')
            append("EVENT_DIRECTORY_ACCESS=")
            append(state.directoryAccessCount)
            append('\n')
            append("EVENT_RAW=")
            append(state.rawEventCount)
            append('\n')
            append("EVENT_INVALID=")
            append(state.invalidEventCount)
            append('\n')
            state.notes.forEach { note ->
                append("NOTE=")
                append(NativePayloadCodec.encodeValue(note))
                append('\n')
            }
        }
    }

    fun decode(raw: String): ThroneHuntCarrierState {
        if (raw.isBlank()) {
            return ThroneHuntCarrierState(
                collection = NativeCollectionStatus.failed(
                    NativeCollectionOutcome.PAYLOAD_REJECTED,
                    IllegalArgumentException("Empty carrier payload"),
                ),
                failureReason = "Empty carrier payload.",
            )
        }
        try {
            NativePayloadContract.requireKeys(
                raw,
                "NATIVE_COLLECTION_OUTCOME",
                "NATIVE_COLLECTION_DETAIL",
                "WATCH_INSTALLED",
                "WATCH_DESCRIPTOR",
                "WATCH_PACKAGE_DIR",
                "EVENT_RAW",
                "EVENT_INVALID",
                "EVENT_DIRECTORY_OPEN",
                "EVENT_DIRECTORY_ACCESS",
            )
        } catch (throwable: Throwable) {
            return ThroneHuntCarrierState(
                collection = NativeCollectionStatus.failed(
                    NativeCollectionOutcome.PAYLOAD_REJECTED,
                    throwable,
                ),
                failureReason = throwable.message,
            )
        }
        var state = ThroneHuntCarrierState()
        val notes = mutableListOf<String>()
        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { line ->
                when {
                    line.startsWith("NOTE=") -> {
                        notes += NativePayloadCodec.decodeValue(line.removePrefix("NOTE="))
                    }

                    line.contains('=') -> {
                        val key = line.substringBefore('=')
                        val value = line.substringAfter('=')
                        state = when (key) {
                            "NATIVE_COLLECTION_OUTCOME" -> state.copy(
                                collection = state.collection.copy(
                                    outcome = runCatching {
                                        NativeCollectionOutcome.valueOf(value)
                                    }.getOrDefault(state.collection.outcome),
                                ),
                            )

                            "NATIVE_COLLECTION_DETAIL" -> state.copy(
                                collection = state.collection.copy(
                                    detail = NativePayloadCodec.decodeValue(value),
                                ),
                            )

                            "WATCH_INSTALLED" -> state.copy(
                                watchInstalled = NativePayloadCodec.decodeFlag(value),
                            )

                            "WATCH_DESCRIPTOR" -> state.copy(
                                watchDescriptor = value.toIntOrNull() ?: state.watchDescriptor,
                            )

                            "WATCH_PACKAGE_DIR" -> state.copy(
                                packageDirectory = NativePayloadCodec.decodeValue(value),
                            )

                            "FAILURE_REASON" -> state.copy(
                                failureReason = NativePayloadCodec.decodeValue(value),
                            )

                            "EVENT_DIRECTORY_OPEN" -> state.copy(
                                directoryOpenCount = value.toIntOrNull() ?: state.directoryOpenCount,
                            )

                            "EVENT_DIRECTORY_ACCESS" -> state.copy(
                                directoryAccessCount = value.toIntOrNull() ?: state.directoryAccessCount,
                            )

                            "EVENT_RAW" -> state.copy(
                                rawEventCount = value.toIntOrNull() ?: state.rawEventCount,
                            )

                            "EVENT_INVALID" -> state.copy(
                                invalidEventCount = value.toIntOrNull() ?: state.invalidEventCount,
                            )

                            else -> state
                        }
                    }
                }
            }
        return state.copy(notes = notes)
    }
}
