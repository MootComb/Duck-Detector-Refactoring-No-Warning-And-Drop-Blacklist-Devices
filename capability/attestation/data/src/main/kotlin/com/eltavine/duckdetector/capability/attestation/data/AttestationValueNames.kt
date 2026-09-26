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

package com.eltavine.duckdetector.capability.attestation.data

import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import java.math.BigInteger
import java.security.MessageDigest
import java.util.Base64

internal fun prettyDn(input: String): String {
    return Regex("CN=([^,]+)").find(input)?.groupValues?.getOrNull(1) ?: input
}

internal fun formatPatchLevel(value: BigInteger, includeDay: Boolean): String? {
    val raw = value.toString().padStart(if (includeDay) 8 else 6, '0')
    return when {
        raw.all { it == '0' } -> null
        includeDay && raw.length >= 8 -> "${raw.substring(0, 4)}-${
            raw.substring(
                4,
                6
            )
        }-${raw.substring(6, 8)}"

        !includeDay && raw.length >= 6 -> "${raw.substring(0, 4)}-${raw.substring(4, 6)}"
        else -> raw
    }
}

internal fun formatOsVersion(value: BigInteger): String {
    val raw = value.toString().padStart(6, '0')
    return "${raw.substring(0, 2).trimStart('0').ifBlank { "0" }}." +
            "${raw.substring(2, 4).trimStart('0').ifBlank { "0" }}." +
            raw.substring(4, 6).trimStart('0').ifBlank { "0" }
}

internal fun formatChallengeSummary(challenge: ByteArray): String {
    return "len=${challenge.size}, sha256=${
        MessageDigest.getInstance("SHA-256").digest(challenge).toHex().take(12)
    }, " +
            "b64=${Base64.getEncoder().encodeToString(challenge).take(18)}"
}

internal fun mapTier(value: Int): TeeTier? {
    return when (value) {
        0 -> TeeTier.SOFTWARE
        1 -> TeeTier.TEE
        2 -> TeeTier.STRONGBOX
        else -> TeeTier.UNKNOWN
    }
}

internal fun mapAlgorithm(value: Int): String = when (value) {
    1 -> "RSA"
    3 -> "EC"
    32 -> "AES"
    128 -> "HMAC"
    else -> "Unknown"
}

internal fun mapPurpose(value: Int): String = when (value) {
    0 -> "Encrypt"
    1 -> "Decrypt"
    2 -> "Sign"
    3 -> "Verify"
    5 -> "Wrap key"
    6 -> "Agree key"
    7 -> "Attest key"
    else -> "Unknown"
}

internal fun mapDigest(value: Int): String = when (value) {
    1 -> "MD5"
    2 -> "SHA-1"
    3 -> "SHA-224"
    4 -> "SHA-256"
    5 -> "SHA-384"
    6 -> "SHA-512"
    else -> "Unknown"
}

internal fun mapPadding(value: Int): String = when (value) {
    1 -> "None"
    2 -> "RSA-OAEP"
    3 -> "RSA-PSS"
    4 -> "RSA-PKCS1-1_5"
    5 -> "PKCS7"
    else -> "Unknown"
}

internal fun mapEcCurve(value: Int): String = when (value) {
    0 -> "P-224"
    1 -> "P-256"
    2 -> "P-384"
    3 -> "P-521"
    4 -> "Curve25519"
    else -> "Unknown"
}

internal fun mapOrigin(value: Int): String = when (value) {
    0 -> "Generated"
    1 -> "Derived"
    2 -> "Imported"
    3 -> "Reserved"
    4 -> "Securely imported"
    else -> "Unknown"
}

internal fun ByteArray.toHex(): String {
    return joinToString(separator = "") { byte -> "%02x".format(byte) }
}
