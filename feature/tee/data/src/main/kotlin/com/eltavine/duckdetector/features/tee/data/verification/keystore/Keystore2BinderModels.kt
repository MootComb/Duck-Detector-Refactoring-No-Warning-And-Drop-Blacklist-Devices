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

import android.os.IBinder
import android.os.Parcel
import com.eltavine.duckdetector.core.platform.PlatformFailureName

data class GenerateKeyReplyCaptureResult(
    val available: Boolean,
    val rawRequest: ByteArray? = null,
    val requestPrefix: String? = null,
    val rawReply: ByteArray? = null,
    val rawPrefix: String? = null,
    val detail: String,
)

data class Keystore2BinderRequest(
    val interfaceDescriptor: String,
    val transactionCode: Int,
    val alias: String,
    val writeTo: (Parcel) -> Unit,
)

data class Keystore2ReplySnapshot(
    val rawPrefix: String? = null,
    val exceptionCode: Int? = null,
    val secondWord: Int? = null,
    val trailingInts: List<Int> = emptyList(),
    val dataSize: Int = 0,
)

data class BinderTransactionResult(
    val success: Boolean,
    val replySnapshot: Keystore2ReplySnapshot? = null,
    val replyFailureReason: String? = null,
    val throwable: Throwable? = null,
)

data class Keystore2PrivateSessionResult(
    val session: Keystore2PrivateSession? = null,
    val failureReason: String? = null,
    val capturedFailures: List<CapturedThrowableRecord> = emptyList(),
)

data class Keystore2PrivateSession(
    val binder: IBinder,
    val service: Any,
    val securityLevel: Any,
    val proxyInstalled: Boolean,
    val serviceProxyActive: Boolean,
    val securityLevelProxyActive: Boolean,
    val diagnosticsCollector: CapturedThrowableCollector = CapturedThrowableCollector(),
)

data class TimingKeyAliases(
    val aliasPrefix: String,
    val attestedAlias: String,
    val nonAttestedAlias: String,
    val attestKeyAlias: String,
)

data class CapturedThrowableRecord(
    val phase: String,
    val summary: String,
    val stackTrace: String,
    val fingerprint: String,
    val occurrenceCount: Int = 1,
)

class CapturedThrowableCollector {
    private val records = LinkedHashMap<String, CapturedThrowableRecord>()

    fun record(
        phase: String,
        summary: String,
        throwable: Throwable,
    ) {
        // 这里按摘要+堆栈去重，保留第一次出现的位置，并累计次数；这样复制出来的 payload 既能静态审查，也不会被重复异常淹没。
        // De-duplicate by summary + stack, keep the first occurrence phase, and accumulate counts so copied payloads stay reviewable instead of noisy.
        val fingerprint = capturedThrowableFingerprint(summary, throwable)
        val current = records[fingerprint]
        records[fingerprint] = if (current == null) {
            CapturedThrowableRecord(
                phase = phase,
                summary = summary,
                stackTrace = throwable.stackTraceToString().trim(),
                fingerprint = fingerprint,
            )
        } else {
            current.copy(occurrenceCount = current.occurrenceCount + 1)
        }
    }

    fun isEmpty(): Boolean = records.isEmpty()

    fun snapshot(): List<CapturedThrowableRecord> = records.values.toList()
}

internal fun keyParameterSetterNameForTag(tag: Int): String {
    val type = tag and 0xf0000000.toInt()
    val tagId = tag and 0x0fffffff
    return when (type) {
        0x10000000, 0x20000000 -> when (tagId) {
            1 -> "setKeyPurpose"
            2 -> "setAlgorithm"
            4 -> "setBlockMode"
            5, 203 -> "setDigest"
            6 -> "setPaddingMode"
            10 -> "setEcCurve"
            304 -> "setSecurityLevel"
            702 -> "setOrigin"
            else -> "setInteger"
        }
        0x30000000, 0x40000000 -> "setInteger"
        0x50000000, 0xA0000000.toInt() -> "setLongInteger"
        0x60000000 -> "setDateTime"
        0x70000000 -> "setBoolValue"
        0x80000000.toInt(), 0x90000000.toInt() -> "setBlob"
        else -> "setInteger"
    }
}

internal fun keyParameterParameterType(value: Any): Class<*> {
    return when (value) {
        is Int -> Int::class.javaPrimitiveType ?: Int::class.java
        is Long -> Long::class.javaPrimitiveType ?: Long::class.java
        is Boolean -> Boolean::class.javaPrimitiveType ?: Boolean::class.java
        else -> value.javaClass
    }
}

internal fun capturedThrowableFingerprint(
    summary: String,
    throwable: Throwable,
): String {
    val root = generateSequence(throwable) { it.cause }.last()
    val frames = root.stackTrace
        .take(6)
        .joinToString("|") { frame -> "${frame.className}.${frame.methodName}:${frame.lineNumber}" }
    return "${PlatformFailureName.of(root)}|$summary|$frames"
}
