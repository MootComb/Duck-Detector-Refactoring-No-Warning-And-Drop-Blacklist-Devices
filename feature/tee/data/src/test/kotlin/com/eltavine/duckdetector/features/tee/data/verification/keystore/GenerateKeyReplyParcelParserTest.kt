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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GenerateKeyReplyParcelParserTest {

    private val parser = GenerateKeyReplyParcelParser()

    @Test
    fun `generate mode fixture keeps hit shape metadata`() {
        val result = parser.parse(rawReply = hexToBytes(GENERATE_MODE_REPLY_HEX))

        assertTrue(result.parseSucceeded)
        assertEquals(13, result.authorizationCount)
        assertEquals(256L, result.lastAuthorizationSecLevel)
        assertEquals(1L, result.lastAuthorizationTag)
        assertEquals(32L, result.lastAuthorizationUnionTag)
        assertTrue(result.lastAuthorizationHasUnknownUnionTag)
        assertEquals(4_294_967_297L, result.modificationTimeMs)
        assertTrue(result.matched)
    }

    @Test
    fun `project docs parcel fingerprint enabled generate mode fixture matches stable fingerprint tuple`() {
        val result = parser.parse(rawReply = hexToBytes(PARCEL_FINGERPRINT_ENABLED_GENERATE_MODE_REPLY_HEX))

        assertTrue(result.parseSucceeded)
        assertEquals(13, result.authorizationCount)
        assertEquals(256L, result.lastAuthorizationSecLevel)
        assertEquals(1L, result.lastAuthorizationTag)
        assertEquals(32L, result.lastAuthorizationUnionTag)
        assertTrue(result.lastAuthorizationHasUnknownUnionTag)
        assertEquals(4_294_967_297L, result.modificationTimeMs)
        assertTrue(result.matched)
    }

    @Test
    fun `stable fingerprint does not depend on authorization count`() {
        val result = parser.parse(rawReply = variableCountGenerateModeReply())

        assertTrue(result.parseSucceeded)
        assertEquals(2, result.authorizationCount)
        assertEquals(256L, result.lastAuthorizationSecLevel)
        assertEquals(1L, result.lastAuthorizationTag)
        assertEquals(32L, result.lastAuthorizationUnionTag)
        assertTrue(result.lastAuthorizationHasUnknownUnionTag)
        assertEquals(4_294_967_297L, result.modificationTimeMs)
        assertTrue(result.matched)
    }

    @Test
    fun `stable fingerprint accepts tee security level in last authorization`() {
        val result = parser.parse(rawReply = variableCountGenerateModeReply(lastSecLevel = 4))

        assertTrue(result.parseSucceeded)
        assertEquals(4L, result.lastAuthorizationSecLevel)
        assertEquals(1L, result.lastAuthorizationTag)
        assertEquals(32L, result.lastAuthorizationUnionTag)
        assertEquals(4_294_967_297L, result.modificationTimeMs)
        assertTrue(result.matched)
    }

    @Test
    fun `normal fixture keeps non hit shape metadata`() {
        val result = parser.parse(rawReply = hexToBytes(NORMAL_REPLY_HEX))

        assertTrue(result.parseSucceeded)
        assertEquals(12, result.authorizationCount)
        assertEquals(20L, result.lastAuthorizationSecLevel)
        assertEquals(1_879_048_695L, result.lastAuthorizationTag)
        assertEquals(1L, result.lastAuthorizationUnionTag)
        assertFalse(result.lastAuthorizationHasUnknownUnionTag)
        assertEquals(4_563_403_454L, result.modificationTimeMs)
        assertFalse(result.matched)
    }

    @Test
    fun `leaf certificate fixture keeps non hit shape metadata`() {
        val result = parser.parse(rawReply = hexToBytes(LEAF_CERTIFICATE_REPLY_HEX))

        assertTrue(result.parseSucceeded)
        assertEquals(12, result.authorizationCount)
        assertEquals(20L, result.lastAuthorizationSecLevel)
        assertEquals(1_879_048_695L, result.lastAuthorizationTag)
        assertEquals(1L, result.lastAuthorizationUnionTag)
        assertFalse(result.lastAuthorizationHasUnknownUnionTag)
        assertEquals(4_563_403_454L, result.modificationTimeMs)
        assertFalse(result.matched)
    }

    @Test
    fun `fingerprint does not match when modification time differs`() {
        val result = parser.parse(rawReply = variableCountGenerateModeReply(modificationTimeMs = 4_294_967_298L))

        assertTrue(result.parseSucceeded)
        assertEquals(256L, result.lastAuthorizationSecLevel)
        assertEquals(32L, result.lastAuthorizationUnionTag)
        assertFalse(result.matched)
    }

    @Test
    fun `fingerprint matches when modification time is above high threshold`() {
        val result = parser.parse(
            rawReply = variableCountGenerateModeReply(
                lastSecLevel = 20,
                lastTag = 0x00000020,
                lastUnionTag = 1,
                modificationTimeMs = 5_000_000_000L,
            ),
        )

        assertTrue(result.parseSucceeded)
        assertEquals(5_000_000_000L, result.modificationTimeMs)
        assertTrue(result.matched)
    }

    @Test
    fun `fingerprint does not match at high threshold boundary without stable tuple`() {
        val result = parser.parse(
            rawReply = variableCountGenerateModeReply(
                lastSecLevel = 20,
                lastTag = 0x00000020,
                lastUnionTag = 1,
                modificationTimeMs = 4_999_999_999L,
            ),
        )

        assertTrue(result.parseSucceeded)
        assertEquals(4_999_999_999L, result.modificationTimeMs)
        assertFalse(result.matched)
    }

    @Test
    fun `fingerprint does not match when last authorization security level differs`() {
        val result = parser.parse(rawReply = variableCountGenerateModeReply(lastSecLevel = 20))

        assertTrue(result.parseSucceeded)
        assertEquals(20L, result.lastAuthorizationSecLevel)
        assertEquals(32L, result.lastAuthorizationUnionTag)
        assertEquals(4_294_967_297L, result.modificationTimeMs)
        assertFalse(result.matched)
    }

    @Test
    fun `fingerprint does not match when last authorization tag differs`() {
        val result = parser.parse(rawReply = variableCountGenerateModeReply(lastTag = 0x00000020))

        assertTrue(result.parseSucceeded)
        assertEquals(256L, result.lastAuthorizationSecLevel)
        assertEquals(32L, result.lastAuthorizationTag)
        assertEquals(32L, result.lastAuthorizationUnionTag)
        assertEquals(4_294_967_297L, result.modificationTimeMs)
        assertFalse(result.matched)
    }

    @Test
    fun `fingerprint does not match when unknown union tag is not on last authorization`() {
        val result = parser.parse(
            rawReply = variableCountGenerateModeReply(
                firstUnionTag = 32,
                lastUnionTag = 1,
            ),
        )

        assertTrue(result.parseSucceeded)
        assertEquals(1L, result.lastAuthorizationUnionTag)
        assertEquals(4_294_967_297L, result.modificationTimeMs)
        assertFalse(result.matched)
    }

    @Test
    fun `fingerprint does not parse failed reply as matched`() {
        val bytes = variableCountGenerateModeReply()
        bytes[0] = 1

        val result = parser.parse(rawReply = bytes)

        assertFalse(result.parseSucceeded)
        assertFalse(result.matched)
    }
}
