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

internal object GenerateKeyParcelDiagnosticFormatter {

    fun format(
        rawRequest: ByteArray?,
        rawReply: ByteArray?,
        parseResult: GenerateKeyReplyParcelParseResult?,
        captureDetail: String,
    ): String {
        return buildString {
            appendLine("=== [GENERATEKEY transaction atomic structure dump] ===")
            appendLine("captureDetail=$captureDetail")
            appendLine()
            appendRequest(rawRequest)
            appendLine()
            appendReply(rawReply, parseResult)
        }.trimEnd()
    }

    private fun StringBuilder.appendRequest(rawRequest: ByteArray?) {
        appendLine("--- [Request Data Parse] ---")
        if (rawRequest == null) {
            appendLine("  Request parcel unavailable.")
            return
        }
        appendLine("  (length: ${rawRequest.size} bytes)")
        runCatching {
            val header = rawRequest.readIntLe(0)
            appendLine("  Offset: 0x0000-0x0004 | interface header: $header")
            val token = rawRequest.readParcelString(4)
            appendLine(
                "  Offset: ${token.range()} | interface descriptor: ${token.value ?: "null"}"
            )
        }.getOrElse { throwable ->
            appendLine("  [!] Request parse interrupted: ${throwable.message ?: PlatformFailureName.of(throwable)}")
        }
        appendLine("--- [Request Raw Hex] ---")
        appendLine(rawRequest.toHexDump())
    }

    private fun StringBuilder.appendReply(
        rawReply: ByteArray?,
        parseResult: GenerateKeyReplyParcelParseResult?,
    ) {
        appendLine("--- [Reply Data Parse] ---")
        if (rawReply == null) {
            appendLine("  Reply parcel unavailable.")
            return
        }
        appendLine("  (length: ${rawReply.size} bytes)")
        val exceptionCode = parseResult?.exceptionCode
        when {
            parseResult == null -> appendLine("  [!] Reply parse unavailable.")
            exceptionCode != null && exceptionCode != 0 -> {
                appendLine("  exception header: $exceptionCode (ERROR)")
                appendLine("  [!] Transaction failed; no KeyMetadata body parsed.")
            }

            !parseResult.parseSucceeded -> appendLine("  [!] Reply parse interrupted.")
            else -> appendKeyMetadata(parseResult)
        }
        appendChecks(parseResult)
        appendLine("--- [Reply Raw Hex] ---")
        appendLine(rawReply.toHexDump())
    }

    private fun StringBuilder.appendKeyMetadata(parsed: GenerateKeyReplyParcelParseResult) {
        appendLine("  exception header: 0 (SUCCESS)")
        appendLine("  [KeyMetadata]:")
        appendLine("    keySecurityLevel: ${parsed.keySecurityLevel}")
        appendLine("    authorizations: ${parsed.authorizations.size}")
        parsed.authorizations.forEachIndexed { index, authorization ->
            appendLine("      [$index] ${authorization.describe()}")
        }
        appendLine("    certificate: ${parsed.certificateLength?.let { "$it bytes" } ?: "null or unreadable"}")
        appendLine("    certificateChain: ${parsed.certificateChainLength?.let { "$it bytes" } ?: "null or unreadable"}")
        appendLine("    modificationTimeMs: ${parsed.modificationTimeMs ?: "unreadable"}")
    }

    private fun StringBuilder.appendChecks(parseResult: GenerateKeyReplyParcelParseResult?) {
        appendLine("  [Keystore2 reply checks]:")
        if (parseResult == null || !parseResult.parseSucceeded) {
            appendLine("    anomaly: not evaluated")
        } else {
            appendLine("    anomaly: ${parseResult.anomaly ?: "none"}")
        }
        parseResult?.let { appendLine("    parser: ${it.detail}") }
    }

    private fun GenerateKeyReplyAuthorization.describe(): String {
        val valueText = when {
            blobLength != null -> "$blobLength bytes"
            value != null -> value.toString()
            else -> "unread"
        }
        val tagType = TAG_TYPE_NAMES.getOrElse(tag ushr TAG_TYPE_SHIFT) { "TYPE_${tag ushr TAG_TYPE_SHIFT}" }
        return "tag=0x${"%08X".format(Locale.US, tag)} ($tagType|${tag and TAG_ID_MASK}) " +
            "level=$securityLevel value[$valueTag]=$valueText @${formatOffsetRange(startOffset, endOffset)}"
    }

    private fun ByteArray.readParcelString(offset: Int): ParcelString {
        val length = readIntLe(offset)
        if (length < 0) {
            return ParcelString(value = null, startOffset = offset, endOffset = offset + INT_SIZE_BYTES)
        }
        val charsOffset = offset + INT_SIZE_BYTES
        val terminatorOffset = charsOffset + (length * Char.SIZE_BYTES)
        require(terminatorOffset + Char.SIZE_BYTES <= size) { "string_truncated@$offset" }
        val chars = CharArray(length) { index ->
            val charOffset = charsOffset + (index * Char.SIZE_BYTES)
            val code = (this[charOffset].toInt() and 0xFF) or
                ((this[charOffset + 1].toInt() and 0xFF) shl Byte.SIZE_BITS)
            code.toChar()
        }
        val endOffset = alignToParcelWord(terminatorOffset + Char.SIZE_BYTES)
        return ParcelString(
            value = chars.concatToString(),
            startOffset = offset,
            endOffset = endOffset,
        )
    }

    private fun ByteArray.readIntLe(offset: Int): Int {
        require(offset >= 0 && offset + INT_SIZE_BYTES <= size) { "int_out_of_bounds@$offset" }
        return (this[offset].toInt() and 0xFF) or
            ((this[offset + 1].toInt() and 0xFF) shl 8) or
            ((this[offset + 2].toInt() and 0xFF) shl 16) or
            ((this[offset + 3].toInt() and 0xFF) shl 24)
    }

    private fun ByteArray.toHexDump(bytesPerLine: Int = HEX_BYTES_PER_LINE): String {
        if (isEmpty()) {
            return ""
        }
        return asList()
            .chunked(bytesPerLine)
            .joinToString(separator = "\n") { line ->
                line.joinToString(separator = " ") { "%02X".format(Locale.US, it.toInt() and 0xFF) }
            }
    }

    private fun ParcelString.range(): String = formatOffsetRange(startOffset, endOffset)

    private fun formatOffsetRange(startOffset: Int, endOffset: Int): String {
        return "0x%04X-0x%04X".format(Locale.US, startOffset, endOffset)
    }

    private fun alignToParcelWord(offset: Int): Int {
        return (offset + PARCEL_WORD_MASK) and PARCEL_WORD_MASK.inv()
    }

    private data class ParcelString(
        val value: String?,
        val startOffset: Int,
        val endOffset: Int,
    )

    private const val INT_SIZE_BYTES = 4
    private const val PARCEL_WORD_MASK = INT_SIZE_BYTES - 1
    private const val HEX_BYTES_PER_LINE = 16
    private const val TAG_TYPE_SHIFT = 28
    private const val TAG_ID_MASK = 0x0FFFFFFF
    private val TAG_TYPE_NAMES = listOf(
        "INVALID", "ENUM", "ENUM_REP", "UINT", "UINT_REP", "ULONG", "DATE", "BOOL", "BIGNUM", "BYTES", "ULONG_REP",
    )
}
