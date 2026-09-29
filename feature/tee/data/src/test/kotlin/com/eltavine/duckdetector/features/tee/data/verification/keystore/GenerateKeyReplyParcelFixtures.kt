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

internal fun hexToBytes(rawHex: String): ByteArray {
    val compact = rawHex.replace(Regex("[^0-9A-Fa-f]"), "")
    require(compact.length % 2 == 0) { "hex fixture must have even length" }
    return ByteArray(compact.length / 2) { index ->
        compact.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }
}

internal data class ReplyAuthorization(
    val securityLevel: Int,
    val tag: Int,
    val valueTag: Int,
    /** The int or long value, or the length of a blob. */
    val value: Long,
)

internal val ALGORITHM_EC = ReplyAuthorization(securityLevel = 1, tag = 0x10000002, valueTag = 1, value = 3)
internal val EC_CURVE_P256 = ReplyAuthorization(securityLevel = 1, tag = 0x1000000A, valueTag = 5, value = 1)
internal val CREATION_DATETIME_KEYSTORE =
    ReplyAuthorization(securityLevel = 100, tag = 0x600002BD, valueTag = 13, value = 1_780_330_308_000L)
internal val USER_ID_SOFTWARE = ReplyAuthorization(securityLevel = 0, tag = 0x300001F5, valueTag = 11, value = 0)

/** What keystore2 over a stock KeyMint returns: KeyMint characteristics, then keystore2's USER_ID. */
internal val STOCK_AUTHORIZATIONS = listOf(ALGORITHM_EC, EC_CURVE_P256, CREATION_DATETIME_KEYSTORE, USER_ID_SOFTWARE)

/** Builds a generateKey reply the way keystore2's Rust AIDL backend writes it. */
internal fun generateKeyReply(
    authorizations: List<ReplyAuthorization> = STOCK_AUTHORIZATIONS,
    exceptionCode: Int = 0,
    modificationTimeMs: Long = 1_780_330_308_917L,
): ByteArray {
    return buildList {
        addIntLe(exceptionCode)
        addParcelable {
            addParcelable {
                addIntLe(4)
                addLongLe(0x1122334455667788L)
                addIntLe(-1)
                addIntLe(-1)
            }
            addIntLe(1)
            addIntLe(authorizations.size)
            authorizations.forEach { authorization ->
                addParcelable {
                    addIntLe(authorization.securityLevel)
                    addParcelable {
                        addIntLe(authorization.tag)
                        addIntLe(1)
                        addIntLe(authorization.valueTag)
                        when (authorization.valueTag) {
                            12, 13 -> addLongLe(authorization.value)
                            14 -> addByteArray(ByteArray(authorization.value.toInt()))
                            else -> addIntLe(authorization.value.toInt())
                        }
                    }
                }
            }
            addByteArray(byteArrayOf(0xAA.toByte()))
            addByteArray(byteArrayOf(0xBB.toByte()))
            addLongLe(modificationTimeMs)
        }
    }.toByteArray()
}

/**
 * The reply from the stock Samsung device in issue #63, up to its last authorization, followed by its
 * certificate and chain lengths with zeroed contents and its modification time.
 */
internal fun samsungStockReply(): ByteArray {
    return buildList {
        addAll(hexToBytes(SAMSUNG_STOCK_REPLY_PREFIX_HEX).asList())
        addByteArray(ByteArray(681))
        addByteArray(ByteArray(2410))
        addLongLe(1_780_330_308_917L)
    }.toByteArray()
}

private fun MutableList<Byte>.addParcelable(fields: MutableList<Byte>.() -> Unit) {
    addIntLe(1)
    val sizeOffset = size
    addIntLe(0)
    fields()
    val parcelableSize = size - sizeOffset
    repeat(Int.SIZE_BYTES) { index ->
        this[sizeOffset + index] = ((parcelableSize ushr (index * Byte.SIZE_BITS)) and 0xFF).toByte()
    }
}

private fun MutableList<Byte>.addByteArray(bytes: ByteArray) {
    addIntLe(bytes.size)
    addAll(bytes.asList())
    padToParcelWord()
}

private fun MutableList<Byte>.addIntLe(value: Int) {
    add((value and 0xFF).toByte())
    add(((value ushr 8) and 0xFF).toByte())
    add(((value ushr 16) and 0xFF).toByte())
    add(((value ushr 24) and 0xFF).toByte())
}

private fun MutableList<Byte>.addLongLe(value: Long) {
    repeat(Long.SIZE_BYTES) { index ->
        add(((value ushr (index * Byte.SIZE_BITS)) and 0xFF).toByte())
    }
}

private fun MutableList<Byte>.padToParcelWord() {
    while (size % Int.SIZE_BYTES != 0) {
        add(0)
    }
}

internal val GENERATE_MODE_REPLY_HEX = """
    00 00 00 00 01 00 00 00 AC 0F 00 00 01 00 00 00
    18 00 00 00 04 00 00 00 17 5C BC 3F B4 F3 50 66
    FF FF FF FF FF FF FF FF 01 00 00 00 0D 00 00 00
    01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
    14 00 00 00 02 00 00 10 01 00 00 00 01 00 00 00
    03 00 00 00 01 00 00 00 20 00 00 00 01 00 00 00
    01 00 00 00 14 00 00 00 0A 00 00 10 01 00 00 00
    05 00 00 00 01 00 00 00 01 00 00 00 20 00 00 00
    01 00 00 00 01 00 00 00 14 00 00 00 01 00 00 20
    01 00 00 00 07 00 00 00 02 00 00 00 01 00 00 00
    20 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00
    05 00 00 20 01 00 00 00 04 00 00 00 04 00 00 00
    01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
    14 00 00 00 03 00 00 30 01 00 00 00 0B 00 00 00
    00 01 00 00 01 00 00 00 20 00 00 00 01 00 00 00
    01 00 00 00 14 00 00 00 F7 01 00 70 01 00 00 00
    0A 00 00 00 01 00 00 00 01 00 00 00 20 00 00 00
    01 00 00 00 01 00 00 00 14 00 00 00 BE 02 00 10
    01 00 00 00 06 00 00 00 00 00 00 00 01 00 00 00
    20 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00
    C1 02 00 30 01 00 00 00 0B 00 00 00 00 71 02 00
    01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
    14 00 00 00 C2 02 00 30 01 00 00 00 0B 00 00 00
    69 17 03 00 01 00 00 00 20 00 00 00 01 00 00 00
    01 00 00 00 14 00 00 00 CE 02 00 30 01 00 00 00
    0B 00 00 00 05 25 35 01 01 00 00 00 20 00 00 00
    01 00 00 00 01 00 00 00 14 00 00 00 CF 02 00 30
    01 00 00 00 0B 00 00 00 05 25 35 01 01 00 00 00
    24 00 00 00 00 00 00 00 01 00 00 00 18 00 00 00
    BD 02 00 60 01 00 00 00 0D 00 00 00 FF 7D 43 77
    9D 01 00 00 01 00 00 00 20 00 00 00 00 00 00 00
    01 00 00 00 14 00 00 00 F5 01 00 30 01 00 00 00
    0B 00 00 00 00 00 00 00 A5 02 00 00 30 82 02 A1
""".trimIndent()

internal val PARCEL_FINGERPRINT_ENABLED_GENERATE_MODE_REPLY_HEX = """
    00 00 00 00 01 00 00 00 30 10 00 00 01 00 00 00
    18 00 00 00 04 00 00 00 D6 AD B5 F4 A6 D8 D0 FD
    FF FF FF FF FF FF FF FF 01 00 00 00 0D 00 00 00
    01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
    14 00 00 00 02 00 00 10 01 00 00 00 01 00 00 00
    03 00 00 00 01 00 00 00 20 00 00 00 01 00 00 00
    01 00 00 00 14 00 00 00 0A 00 00 10 01 00 00 00
    05 00 00 00 01 00 00 00 01 00 00 00 20 00 00 00
    01 00 00 00 01 00 00 00 14 00 00 00 01 00 00 20
    01 00 00 00 07 00 00 00 02 00 00 00 01 00 00 00
    20 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00
    05 00 00 20 01 00 00 00 04 00 00 00 04 00 00 00
    01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
    14 00 00 00 03 00 00 30 01 00 00 00 0B 00 00 00
    00 01 00 00 01 00 00 00 20 00 00 00 01 00 00 00
    01 00 00 00 14 00 00 00 F7 01 00 70 01 00 00 00
    0A 00 00 00 01 00 00 00 01 00 00 00 20 00 00 00
    01 00 00 00 01 00 00 00 14 00 00 00 BE 02 00 10
    01 00 00 00 06 00 00 00 00 00 00 00 01 00 00 00
    20 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00
    C1 02 00 30 01 00 00 00 0B 00 00 00 00 71 02 00
    01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
    14 00 00 00 C2 02 00 30 01 00 00 00 0B 00 00 00
    6D 17 03 00 01 00 00 00 20 00 00 00 01 00 00 00
    01 00 00 00 14 00 00 00 CE 02 00 30 01 00 00 00
    0B 00 00 00 99 26 35 01 01 00 00 00 20 00 00 00
    01 00 00 00 01 00 00 00 14 00 00 00 CF 02 00 30
    01 00 00 00 0B 00 00 00 99 26 35 01 01 00 00 00
    24 00 00 00 64 00 00 00 01 00 00 00 18 00 00 00
    BD 02 00 60 01 00 00 00 0D 00 00 00 07 2E 17 43
    9E 01 00 00 01 00 00 00 20 00 00 00 64 00 00 00
    01 00 00 00 14 00 00 00 F5 01 00 30 01 00 00 00
    0B 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00
    AA 00 00 00 01 00 00 00 01 00 00 00 BB 00 00 00
    01 00 00 00 01 00 00 00
""".trimIndent()

internal val NORMAL_REPLY_HEX = """
    00 00 00 00 01 00 00 00 84 0F 00 00 01 00 00 00
    18 00 00 00 04 00 00 00 F2 BA 9D E8 1B 29 76 80
    FF FF FF FF FF FF FF FF 01 00 00 00 0C 00 00 00
    01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
    14 00 00 00 01 00 00 20 01 00 00 00 07 00 00 00
    02 00 00 00 01 00 00 00 20 00 00 00 01 00 00 00
    01 00 00 00 14 00 00 00 02 00 00 10 01 00 00 00
    01 00 00 00 03 00 00 00 01 00 00 00 20 00 00 00
    01 00 00 00 01 00 00 00 14 00 00 00 05 00 00 20
    01 00 00 00 04 00 00 00 04 00 00 00 01 00 00 00
    20 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00
    0A 00 00 10 01 00 00 00 05 00 00 00 01 00 00 00
    01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
    14 00 00 00 F7 01 00 70 01 00 00 00 0A 00 00 00
    01 00 00 00 01 00 00 00 20 00 00 00 01 00 00 00
    01 00 00 00 14 00 00 00 BE 02 00 10 01 00 00 00
    06 00 00 00 00 00 00 00 01 00 00 00 20 00 00 00
    01 00 00 00 01 00 00 00 14 00 00 00 C1 02 00 30
    01 00 00 00 0B 00 00 00 00 71 02 00 01 00 00 00
    20 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00
    C2 02 00 30 01 00 00 00 0B 00 00 00 69 17 03 00
    01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
    14 00 00 00 CE 02 00 30 01 00 00 00 0B 00 00 00
    05 25 35 01 01 00 00 00 20 00 00 00 01 00 00 00
    01 00 00 00 14 00 00 00 CF 02 00 30 01 00 00 00
    0B 00 00 00 05 25 35 01 01 00 00 00 24 00 00 00
    64 00 00 00 01 00 00 00 18 00 00 00 BD 02 00 60
    01 00 00 00 0D 00 00 00 CB 85 57 77 9D 01 00 00
    01 00 00 00 20 00 00 00 00 00 00 00 01 00 00 00
    14 00 00 00 F5 01 00 30 01 00 00 00 0B 00 00 00
    00 00 00 00 A1 02 00 00 30 82 02 9D
""".trimIndent()

internal val LEAF_CERTIFICATE_REPLY_HEX = """
    00 00 00 00 01 00 00 00 84 0F 00 00 01 00 00 00
    18 00 00 00 04 00 00 00 BC 84 B4 88 D4 43 F5 FE
    FF FF FF FF FF FF FF FF 01 00 00 00 0C 00 00 00
    01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
    14 00 00 00 01 00 00 20 01 00 00 00 07 00 00 00
    02 00 00 00 01 00 00 00 20 00 00 00 01 00 00 00
    01 00 00 00 14 00 00 00 02 00 00 10 01 00 00 00
    01 00 00 00 03 00 00 00 01 00 00 00 20 00 00 00
    01 00 00 00 01 00 00 00 14 00 00 00 05 00 00 20
    01 00 00 00 04 00 00 00 04 00 00 00 01 00 00 00
    20 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00
    0A 00 00 10 01 00 00 00 05 00 00 00 01 00 00 00
    01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
    14 00 00 00 F7 01 00 70 01 00 00 00 0A 00 00 00
    01 00 00 00 01 00 00 00 20 00 00 00 01 00 00 00
    01 00 00 00 14 00 00 00 BE 02 00 10 01 00 00 00
    06 00 00 00 00 00 00 00 01 00 00 00 20 00 00 00
    01 00 00 00 01 00 00 00 14 00 00 00 C1 02 00 30
    01 00 00 00 0B 00 00 00 00 71 02 00 01 00 00 00
    20 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00
    C2 02 00 30 01 00 00 00 0B 00 00 00 69 17 03 00
    01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
    14 00 00 00 CE 02 00 30 01 00 00 00 0B 00 00 00
    05 25 35 01 01 00 00 00 20 00 00 00 01 00 00 00
    01 00 00 00 14 00 00 00 CF 02 00 30 01 00 00 00
    0B 00 00 00 05 25 35 01 01 00 00 00 24 00 00 00
    64 00 00 00 01 00 00 00 18 00 00 00 BD 02 00 60
    01 00 00 00 0D 00 00 00 5E FA 46 77 9D 01 00 00
    01 00 00 00 20 00 00 00 00 00 00 00 01 00 00 00
    14 00 00 00 F5 01 00 30 01 00 00 00 0B 00 00 00
    00 00 00 00 A3 02 00 00 30 82 02 9F
""".trimIndent()

internal val SAMSUNG_STOCK_REPLY_PREFIX_HEX = """
    00 00 00 00 01 00 00 00 04 0E 00 00 01 00 00 00
    18 00 00 00 04 00 00 00 E1 C0 5D 8D A6 32 2A 9A
    FF FF FF FF FF FF FF FF 01 00 00 00 0C 00 00 00
    01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
    14 00 00 00 02 00 00 10 01 00 00 00 01 00 00 00
    03 00 00 00 01 00 00 00 20 00 00 00 01 00 00 00
    01 00 00 00 14 00 00 00 0A 00 00 10 01 00 00 00
    05 00 00 00 01 00 00 00 01 00 00 00 20 00 00 00
    01 00 00 00 01 00 00 00 14 00 00 00 BE 02 00 10
    01 00 00 00 06 00 00 00 00 00 00 00 01 00 00 00
    20 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00
    01 00 00 20 01 00 00 00 07 00 00 00 02 00 00 00
    01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
    14 00 00 00 05 00 00 20 01 00 00 00 04 00 00 00
    04 00 00 00 01 00 00 00 20 00 00 00 01 00 00 00
    01 00 00 00 14 00 00 00 F7 01 00 70 01 00 00 00
    0A 00 00 00 01 00 00 00 01 00 00 00 20 00 00 00
    01 00 00 00 01 00 00 00 14 00 00 00 C1 02 00 30
    01 00 00 00 0B 00 00 00 E0 22 02 00 01 00 00 00
    20 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00
    C2 02 00 30 01 00 00 00 0B 00 00 00 06 17 03 00
    01 00 00 00 20 00 00 00 01 00 00 00 01 00 00 00
    14 00 00 00 CE 02 00 30 01 00 00 00 0B 00 00 00
    59 FE 34 01 01 00 00 00 20 00 00 00 01 00 00 00
    01 00 00 00 14 00 00 00 CF 02 00 30 01 00 00 00
    0B 00 00 00 59 FE 34 01 01 00 00 00 24 00 00 00
    64 00 00 00 01 00 00 00 18 00 00 00 BD 02 00 60
    01 00 00 00 0D 00 00 00 29 A5 F4 83 9E 01 00 00
    01 00 00 00 20 00 00 00 00 00 00 00 01 00 00 00
    14 00 00 00 F5 01 00 30 01 00 00 00 0B 00 00 00
    00 00 00 00
""".trimIndent()
