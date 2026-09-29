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

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GenerateKeyParcelDiagnosticFormatterTest {

    private val parser = GenerateKeyReplyParcelParser()

    @Test
    fun `formatter lists the parsed authorizations and the reply checks`() {
        val rawReply = generateKeyReply(
            listOf(ALGORITHM_EC, CREATION_DATETIME_KEYSTORE.copy(securityLevel = 0), USER_ID_SOFTWARE),
        )
        val diagnostic = GenerateKeyParcelDiagnosticFormatter.format(
            rawRequest = generateKeyRequest(),
            rawReply = rawReply,
            parseResult = parser.parse(rawReply = rawReply),
            captureDetail = "captured for test",
        )

        assertTrue(diagnostic.contains("GENERATEKEY transaction atomic structure dump"))
        assertTrue(diagnostic.contains("interface descriptor: android.system.keystore2.IKeystoreSecurityLevel"))
        assertTrue(diagnostic.contains("authorizations: 3"))
        assertTrue(diagnostic.contains("tag=0x600002BD (DATE|701) level=0 value[13]=1780330308000"))
        assertTrue(diagnostic.contains("tag=0x300001F5 (UINT|501) level=0 value[11]=0"))
        assertTrue(diagnostic.contains("modificationTimeMs: 1780330308917"))
        assertTrue(diagnostic.contains("anomaly: CREATION_DATETIME_OUTSIDE_KEYSTORE"))
        assertTrue(diagnostic.contains("--- [Reply Raw Hex] ---"))
    }

    @Test
    fun `formatter keeps failure replies as diagnostic detail only`() {
        val rawReply = generateKeyReply(exceptionCode = 1)
        val diagnostic = GenerateKeyParcelDiagnosticFormatter.format(
            rawRequest = null,
            rawReply = rawReply,
            parseResult = parser.parse(rawReply = rawReply),
            captureDetail = "captured failed reply",
        )

        assertTrue(diagnostic.contains("exception header: 1 (ERROR)"))
        assertTrue(diagnostic.contains("anomaly: not evaluated"))
        assertFalse(diagnostic.contains("[KeyMetadata]"))
    }

    private fun generateKeyRequest(): ByteArray {
        return buildList {
            addIntLe(0)
            addParcelString("android.system.keystore2.IKeystoreSecurityLevel")
        }.toByteArray()
    }

    private fun MutableList<Byte>.addParcelString(value: String) {
        addIntLe(value.length)
        value.forEach { char ->
            add((char.code and 0xFF).toByte())
            add(((char.code ushr Byte.SIZE_BITS) and 0xFF).toByte())
        }
        add(0)
        add(0)
        while (size % Int.SIZE_BYTES != 0) {
            add(0)
        }
    }

    private fun MutableList<Byte>.addIntLe(value: Int) {
        add((value and 0xFF).toByte())
        add(((value ushr 8) and 0xFF).toByte())
        add(((value ushr 16) and 0xFF).toByte())
        add(((value ushr 24) and 0xFF).toByte())
    }
}
