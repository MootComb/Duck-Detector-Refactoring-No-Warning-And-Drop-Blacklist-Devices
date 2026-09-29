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

import com.eltavine.duckdetector.core.platform.PlatformFailureName
import java.util.Locale

/** Why a generateKey reply could not have come from keystore2 over a stock KeyMint. */
enum class GenerateKeyReplyAnomaly {
    /**
     * The last authorization is not a SOFTWARE-level USER_ID. keystore2's store_new_key appends one
     * after the KeyMint characteristics of every key it stores, so keystore2 did not assemble this
     * reply.
     * https://android.googlesource.com/platform/system/security/+/refs/heads/main/keystore2/src/security_level.rs
     */
    USER_ID_NOT_APPENDED_BY_KEYSTORE,

    /**
     * CREATION_DATETIME came back outside the KEYSTORE level. The KeyMint spec only requires it to be
     * software-enforced, but the Rust and C++ reference KeyMint and km_compat all return it at
     * KEYSTORE, so another level is a lead rather than proof.
     * https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/keymint/aidl/android/hardware/security/keymint/Tag.aidl
     * https://android.googlesource.com/platform/system/keymint/+/refs/heads/main/common/src/tag/info.rs
     */
    CREATION_DATETIME_OUTSIDE_KEYSTORE,
}

data class GenerateKeyReplyAuthorization(
    val securityLevel: Int,
    val tag: Int,
    val valueTag: Int,
    /** The enum, boolean, integer or date value; null for a blob or an unknown member. */
    val value: Long?,
    /** The length of a blob value; null for every other member. */
    val blobLength: Int?,
    val startOffset: Int,
    val endOffset: Int,
)

/**
 * [parseSucceeded] covers the fields the checks read, up to the authorizations. The certificate, the
 * chain and the modification time stay null when the rest of the reply cannot be read.
 */
data class GenerateKeyReplyParcelParseResult(
    val parseSucceeded: Boolean,
    val exceptionCode: Int? = null,
    val keySecurityLevel: Int? = null,
    val authorizations: List<GenerateKeyReplyAuthorization> = emptyList(),
    val certificateLength: Int? = null,
    val certificateChainLength: Int? = null,
    val modificationTimeMs: Long? = null,
    val anomaly: GenerateKeyReplyAnomaly? = null,
    val rawPrefix: String?,
    val detail: String,
)

class GenerateKeyReplyParcelParser {

    fun parse(rawReply: ByteArray, rawPrefix: String? = null): GenerateKeyReplyParcelParseResult {
        val resolvedRawPrefix = rawPrefix ?: rawReply.toHexPrefix()
        var exceptionCode: Int? = null
        return runCatching {
            val reader = ParcelReader(rawReply)
            exceptionCode = reader.readInt()
            require(exceptionCode == 0) { "unexpected_exception_code=$exceptionCode" }
            // keystore2 writes stable AIDL through the Rust backend: a non-null marker before every
            // parcelable and union, and a size header that counts itself at the start of every
            // parcelable. The size headers bound each field, so fields added later are skipped.
            // https://android.googlesource.com/platform/frameworks/native/+/refs/heads/main/libs/binder/rust/src/parcel.rs
            reader.expectNonNull("key_metadata")
            reader.readParcelableEnd()
            reader.expectNonNull("key_descriptor")
            reader.skipTo(reader.readParcelableEnd(), "key_descriptor")
            val keySecurityLevel = reader.readInt()
            val authorizationCount = reader.readInt()
            require(authorizationCount in 0..MAX_AUTHORIZATION_COUNT) {
                "authorization_count_out_of_range=$authorizationCount"
            }
            val authorizations = List(authorizationCount) { readAuthorization(reader) }
            val tail = runCatching { readTail(reader) }
            val anomaly = anomalyOf(authorizations)
            GenerateKeyReplyParcelParseResult(
                parseSucceeded = true,
                exceptionCode = exceptionCode,
                keySecurityLevel = keySecurityLevel,
                authorizations = authorizations,
                certificateLength = tail.getOrNull()?.certificateLength,
                certificateChainLength = tail.getOrNull()?.certificateChainLength,
                modificationTimeMs = tail.getOrNull()?.modificationTimeMs,
                anomaly = anomaly,
                rawPrefix = resolvedRawPrefix,
                detail = listOf(
                    "parseSucceeded=true",
                    "rawSize=${rawReply.size}",
                    "keySecurityLevel=$keySecurityLevel",
                    "authorizationCount=$authorizationCount",
                    "lastAuthorization=${authorizations.lastOrNull()?.describe() ?: "none"}",
                    "creationDatetimeLevels=${authorizations.creationDatetimeLevels()}",
                    "tail=${tail.fold({ it.describe() }, { it.message ?: PlatformFailureName.of(it) })}",
                    "anomaly=${anomaly ?: "none"}",
                ).joinToString(separator = ";"),
            )
        }.getOrElse { throwable ->
            GenerateKeyReplyParcelParseResult(
                parseSucceeded = false,
                exceptionCode = exceptionCode,
                rawPrefix = resolvedRawPrefix,
                detail = listOf(
                    "parseSucceeded=false",
                    "rawSize=${rawReply.size}",
                    "reason=${throwable.message ?: PlatformFailureName.of(throwable)}",
                ).joinToString(separator = ";"),
            )
        }
    }

    private fun readAuthorization(reader: ParcelReader): GenerateKeyReplyAuthorization {
        val startOffset = reader.position
        reader.expectNonNull("authorization")
        val authorizationEnd = reader.readParcelableEnd()
        val securityLevel = reader.readInt()
        reader.expectNonNull("key_parameter")
        val parameterEnd = reader.readParcelableEnd()
        require(parameterEnd <= authorizationEnd) { "key_parameter_overruns_authorization@$startOffset" }
        val tag = reader.readInt()
        reader.expectNonNull("key_parameter_value")
        val valueTag = reader.readInt()
        var value: Long? = null
        var blobLength: Int? = null
        when (valueTag) {
            in INT_VALUE_TAGS -> value = reader.readInt().toLong()
            in LONG_VALUE_TAGS -> value = reader.readLong()
            BLOB_VALUE_TAG -> blobLength = reader.skipByteArray("key_parameter_blob")
        }
        reader.skipTo(parameterEnd, "key_parameter")
        reader.skipTo(authorizationEnd, "authorization")
        return GenerateKeyReplyAuthorization(
            securityLevel = securityLevel,
            tag = tag,
            valueTag = valueTag,
            value = value,
            blobLength = blobLength,
            startOffset = startOffset,
            endOffset = authorizationEnd,
        )
    }

    private fun readTail(reader: ParcelReader): ReplyTail {
        return ReplyTail(
            certificateLength = reader.skipNullableByteArray("certificate"),
            certificateChainLength = reader.skipNullableByteArray("certificate_chain"),
            modificationTimeMs = reader.readLong(),
        )
    }

    private fun anomalyOf(authorizations: List<GenerateKeyReplyAuthorization>): GenerateKeyReplyAnomaly? {
        val last = authorizations.lastOrNull()
        return when {
            last == null || last.tag != TAG_USER_ID || last.securityLevel != SECURITY_LEVEL_SOFTWARE ->
                GenerateKeyReplyAnomaly.USER_ID_NOT_APPENDED_BY_KEYSTORE

            authorizations.any { it.tag == TAG_CREATION_DATETIME && it.securityLevel != SECURITY_LEVEL_KEYSTORE } ->
                GenerateKeyReplyAnomaly.CREATION_DATETIME_OUTSIDE_KEYSTORE

            else -> null
        }
    }

    private fun GenerateKeyReplyAuthorization.describe(): String {
        return "0x${"%08X".format(Locale.ROOT, tag)}@$securityLevel"
    }

    private fun List<GenerateKeyReplyAuthorization>.creationDatetimeLevels(): String {
        return filter { it.tag == TAG_CREATION_DATETIME }
            .joinToString(separator = ",") { it.securityLevel.toString() }
            .ifEmpty { "none" }
    }

    private fun ByteArray.toHexPrefix(maxBytes: Int = DEFAULT_PREFIX_BYTES): String {
        return take(maxBytes).joinToString(" ") { "%02X".format(it.toInt() and 0xFF) }
    }

    private data class ReplyTail(
        val certificateLength: Int?,
        val certificateChainLength: Int?,
        val modificationTimeMs: Long,
    ) {
        fun describe(): String {
            return "certificate=${certificateLength ?: "null"},chain=${certificateChainLength ?: "null"}," +
                "modificationTimeMs=$modificationTimeMs"
        }
    }

    private class ParcelReader(private val bytes: ByteArray) {
        var position: Int = 0
            private set

        fun readInt(): Int {
            require(position >= 0 && position + Int.SIZE_BYTES <= bytes.size) { "int_out_of_bounds@$position" }
            val value = (bytes[position].toInt() and 0xFF) or
                ((bytes[position + 1].toInt() and 0xFF) shl 8) or
                ((bytes[position + 2].toInt() and 0xFF) shl 16) or
                ((bytes[position + 3].toInt() and 0xFF) shl 24)
            position += Int.SIZE_BYTES
            return value
        }

        fun readLong(): Long {
            require(position >= 0 && position + Long.SIZE_BYTES <= bytes.size) { "long_out_of_bounds@$position" }
            val value = (0 until Long.SIZE_BYTES).fold(0L) { acc, index ->
                acc or ((bytes[position + index].toLong() and 0xFFL) shl (index * Byte.SIZE_BITS))
            }
            position += Long.SIZE_BYTES
            return value
        }

        fun expectNonNull(label: String) {
            val marker = readInt()
            require(marker == NON_NULL_MARKER) { "${label}_marker=$marker" }
        }

        /** Reads a parcelable's size header and returns the offset its fields end at. */
        fun readParcelableEnd(): Int {
            val start = position
            val size = readInt()
            require(size >= Int.SIZE_BYTES) { "parcelable_size=$size@$start" }
            return start + size
        }

        fun skipTo(end: Int, label: String) {
            require(end in position..bytes.size) { "${label}_end=$end@$position" }
            position = end
        }

        fun skipByteArray(label: String): Int {
            val length = readInt()
            require(length >= 0) { "${label}_length=$length" }
            skipTo(alignToParcelWord(position + length), label)
            return length
        }

        fun skipNullableByteArray(label: String): Int? {
            val length = readInt()
            if (length == NULL_LENGTH) {
                return null
            }
            require(length >= 0) { "${label}_length=$length" }
            skipTo(alignToParcelWord(position + length), label)
            return length
        }

        private fun alignToParcelWord(offset: Int): Int {
            return (offset + PARCEL_WORD_MASK) and PARCEL_WORD_MASK.inv()
        }
    }

    private companion object {
        const val DEFAULT_PREFIX_BYTES = 32
        const val PARCEL_WORD_MASK = Int.SIZE_BYTES - 1
        const val NON_NULL_MARKER = 1
        const val NULL_LENGTH = -1
        const val MAX_AUTHORIZATION_COUNT = 256
        const val SECURITY_LEVEL_SOFTWARE = 0
        const val SECURITY_LEVEL_KEYSTORE = 100
        const val TAG_USER_ID = 0x300001F5
        const val TAG_CREATION_DATETIME = 0x600002BD

        // KeyParameterValue members: invalid, the enums, boolValue and integer are int32; longInteger
        // and dateTime are int64; blob is a byte array.
        val INT_VALUE_TAGS = 0..11
        val LONG_VALUE_TAGS = 12..13
        const val BLOB_VALUE_TAG = 14
    }
}
