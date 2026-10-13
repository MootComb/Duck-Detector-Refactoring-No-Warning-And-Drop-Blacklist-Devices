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

/** Encodes the status mmap ABI section of the context validity payload; decoded by SelinuxContextValidityBridge. */
internal fun StringBuilder.appendStatusAbi(snapshot: SelinuxContextValiditySnapshot) {
    append("STATUS_ABI_ATTEMPTED=")
        .append(if (snapshot.statusAbi.attempted) '1' else '0')
        .append('\n')
    append("STATUS_ABI_STATE=")
        .append(NativePayloadCodec.encodeValue(snapshot.statusAbi.state.name))
        .append('\n')
    snapshot.statusAbi.violatedRequests.takeIf { it.isNotEmpty() }?.let { requests ->
        append("STATUS_ABI_VIOLATED=")
            .append(NativePayloadCodec.encodeValue(requests.joinToString(",") { it.name }))
            .append('\n')
    }
    snapshot.statusAbi.pageSize?.let {
        append("STATUS_ABI_PAGE_SIZE=").append(it).append('\n')
    }
    snapshot.statusAbi.failureReason?.takeIf { it.isNotEmpty() }?.let {
        append("STATUS_ABI_FAILURE_REASON=")
            .append(NativePayloadCodec.encodeValue(it))
            .append('\n')
    }
    snapshot.statusAbi.notes.forEach { note ->
        append("STATUS_ABI_NOTE=").append(NativePayloadCodec.encodeValue(note)).append('\n')
    }
}
