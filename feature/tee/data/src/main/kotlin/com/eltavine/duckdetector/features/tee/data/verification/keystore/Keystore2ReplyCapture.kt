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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import java.lang.reflect.Method

internal data class HiddenMethodInvocation(
    val target: Any,
    val method: Method,
    val args: Array<Any?>,
)

internal data class GenerateKeyReplyCaptureSnapshot(
    val rawRequest: ByteArray? = null,
    val requestPrefix: String? = null,
    val rawReply: ByteArray? = null,
    val rawPrefix: String? = null,
    val transactionCode: Int? = null,
    val transactReturned: Boolean? = null,
    val throwable: Throwable? = null,
    val failureReason: String? = null,
)

internal class GenerateKeyReplyCaptureSlot {
    var rawRequest: ByteArray? = null
    var requestPrefix: String? = null
    var rawReply: ByteArray? = null
    var rawPrefix: String? = null
    var transactionCode: Int? = null
    var transactReturned: Boolean? = null
    var failureReason: String? = null
    var completed: Boolean = false

    fun toSnapshot(
        throwable: Throwable? = null,
        defaultFailureReason: String,
    ): GenerateKeyReplyCaptureSnapshot {
        return GenerateKeyReplyCaptureSnapshot(
            rawRequest = rawRequest,
            requestPrefix = requestPrefix,
            rawReply = rawReply,
            rawPrefix = rawPrefix,
            transactionCode = transactionCode,
            transactReturned = transactReturned,
            throwable = throwable,
            failureReason = failureReason ?: if (rawReply == null) defaultFailureReason else null,
        )
    }
}
