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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class GenerateKeyReplyParcelParserTest {

    private val parser = GenerateKeyReplyParcelParser()

    @Test
    fun `stock Samsung reply parses to its last byte and stays clean`() {
        val result = parser.parse(rawReply = samsungStockReply())

        assertTrue(result.parseSucceeded)
        assertEquals(1, result.keySecurityLevel)
        assertEquals(12, result.authorizations.size)
        assertEquals(681, result.certificateLength)
        assertEquals(2410, result.certificateChainLength)
        assertEquals(1_780_330_308_917L, result.modificationTimeMs)
        assertNull(result.anomaly)
    }

    @Test
    fun `stock replies with a truncated certificate stay clean`() {
        listOf(NORMAL_REPLY_HEX, LEAF_CERTIFICATE_REPLY_HEX).forEach { hex ->
            val result = parser.parse(rawReply = hexToBytes(hex))

            assertTrue(result.parseSucceeded)
            assertEquals(12, result.authorizations.size)
            assertNull(result.modificationTimeMs)
            assertNull(result.anomaly)
        }
    }

    @Test
    fun `generate mode reply with a software creation datetime needs review`() {
        val result = parser.parse(rawReply = hexToBytes(GENERATE_MODE_REPLY_HEX))

        assertTrue(result.parseSucceeded)
        assertEquals(13, result.authorizations.size)
        assertEquals(0x300001F5, result.authorizations.last().tag)
        assertEquals(0, result.authorizations.last().securityLevel)
        assertEquals(GenerateKeyReplyAnomaly.CREATION_DATETIME_OUTSIDE_KEYSTORE, result.anomaly)
    }

    @Test
    fun `generate mode reply with a keystore level user id was not assembled by keystore2`() {
        val result = parser.parse(rawReply = hexToBytes(PARCEL_FINGERPRINT_ENABLED_GENERATE_MODE_REPLY_HEX))

        assertTrue(result.parseSucceeded)
        assertEquals(100, result.authorizations.last().securityLevel)
        assertEquals(GenerateKeyReplyAnomaly.USER_ID_NOT_APPENDED_BY_KEYSTORE, result.anomaly)
    }

    @Test
    fun `built stock reply reads every field`() {
        val result = parser.parse(rawReply = generateKeyReply())

        assertTrue(result.parseSucceeded)
        assertEquals(listOf(3L, 1L, 1_780_330_308_000L, 0L), result.authorizations.map { it.value })
        assertEquals(1, result.certificateLength)
        assertEquals(1, result.certificateChainLength)
        assertEquals(1_780_330_308_917L, result.modificationTimeMs)
        assertNull(result.anomaly)
    }

    @Test
    fun `user id that keystore2 did not append is an anomaly`() {
        val cases = listOf(
            STOCK_AUTHORIZATIONS.dropLast(1) + USER_ID_SOFTWARE.copy(securityLevel = 100),
            listOf(USER_ID_SOFTWARE, ALGORITHM_EC, EC_CURVE_P256, CREATION_DATETIME_KEYSTORE),
            STOCK_AUTHORIZATIONS.dropLast(1),
            emptyList(),
        )

        cases.forEach { authorizations ->
            val result = parser.parse(rawReply = generateKeyReply(authorizations))

            assertTrue(result.parseSucceeded)
            assertEquals(GenerateKeyReplyAnomaly.USER_ID_NOT_APPENDED_BY_KEYSTORE, result.anomaly)
        }
    }

    @Test
    fun `creation datetime outside keystore needs review but its absence does not`() {
        val softwareDatetime = parser.parse(
            rawReply = generateKeyReply(
                listOf(ALGORITHM_EC, CREATION_DATETIME_KEYSTORE.copy(securityLevel = 0), USER_ID_SOFTWARE),
            ),
        )
        val noDatetime = parser.parse(rawReply = generateKeyReply(listOf(ALGORITHM_EC, USER_ID_SOFTWARE)))

        assertEquals(GenerateKeyReplyAnomaly.CREATION_DATETIME_OUTSIDE_KEYSTORE, softwareDatetime.anomaly)
        assertNull(noDatetime.anomaly)
    }

    @Test
    fun `blob and unknown values are skipped by their size headers`() {
        val applicationId = ReplyAuthorization(securityLevel = 100, tag = 0x90000259.toInt(), valueTag = 14, value = 5)
        val unknownValue = ReplyAuthorization(securityLevel = 1, tag = 0x30000003, valueTag = 32, value = 7)
        val result = parser.parse(
            rawReply = generateKeyReply(listOf(applicationId, unknownValue) + STOCK_AUTHORIZATIONS),
        )

        assertTrue(result.parseSucceeded)
        assertEquals(5, result.authorizations.first().blobLength)
        assertNull(result.authorizations[1].value)
        assertEquals(1_780_330_308_917L, result.modificationTimeMs)
        assertNull(result.anomaly)
    }

    @Test
    fun `failed or malformed replies do not parse`() {
        val failed = generateKeyReply(exceptionCode = 1)
        val nullMetadata = generateKeyReply().also { it[4] = 0 }
        val oversizedAuthorization = generateKeyReply().also { it[53] = 0x7F }

        listOf(failed, nullMetadata, oversizedAuthorization).forEach { rawReply ->
            val result = parser.parse(rawReply = rawReply)

            assertFalse(result.parseSucceeded)
            assertNull(result.anomaly)
        }
        assertEquals(1, parser.parse(rawReply = failed).exceptionCode)
    }
}
