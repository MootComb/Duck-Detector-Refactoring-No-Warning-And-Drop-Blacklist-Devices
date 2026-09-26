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

package com.eltavine.duckdetector.features.tee.data.verification.crl

import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefs
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkMode
import java.net.SocketTimeoutException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CrlStatusServiceFailureTest {

    @Test
    fun `reports timeout detail while using built in snapshot`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { true },
            feedFetcher = CrlFeedFetcher { throw SocketTimeoutException("timeout") },
            embeddedStatusProvider = embeddedStatusProvider("""{"entries":{}}"""),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ERROR, result.networkState.mode)
        assertTrue(result.networkState.summary.contains("built-in revocation snapshot was used"))
        assertTrue(result.networkState.detail.orEmpty().contains("timed out"))
        assertTrue(result.networkState.usedCache)
    }

    @Test
    fun `reports online parse error while using built in snapshot`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { true },
            feedFetcher = CrlFeedFetcher { """{"entries":""" },
            embeddedStatusProvider = embeddedStatusProvider("""{"entries":{}}"""),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ERROR, result.networkState.mode)
        assertTrue(result.networkState.detail.orEmpty().contains("parsed"))
        assertTrue(result.networkState.usedCache)
    }

    @Test
    fun `reports malformed online feed while using built in snapshot`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { true },
            feedFetcher = CrlFeedFetcher { """{"entries":[]}""" },
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{"1":{"status":"REVOKED","reason":"embedded"}}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ERROR, result.networkState.mode)
        assertTrue(result.networkState.detail.orEmpty().contains("missing an entries object"))
        assertTrue(result.networkState.usedCache)
        assertEquals(1, result.revokedCertificates.size)
    }

    @Test
    fun `clears legacy cache and uses embedded snapshot as fallback`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = """{"entries":{"1":{"status":"REVOKED","reason":"cached"}}}""",
                crlFetchedAt = NOW - 1_000L,
            ),
        )
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { true },
            feedFetcher = CrlFeedFetcher { throw IllegalStateException("boom") },
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{"1":{"status":"REVOKED","reason":"embedded"}}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ERROR, result.networkState.mode)
        assertTrue(result.networkState.usingCacheFallback)
        assertTrue(result.networkState.usedCache)
        assertEquals(1, result.revokedCertificates.size)
        assertEquals(null, store.current.crlCacheJson)
        assertEquals(0L, store.current.crlFetchedAt)
    }

    @Test
    fun `unanswered online refresh consent still uses built in snapshot`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = false,
                consentGranted = false,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )
        var fetchCalled = false
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { true },
            feedFetcher = CrlFeedFetcher {
                fetchCalled = true
                """{"entries":{}}"""
            },
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{"1":{"status":"REVOKED","reason":"embedded"}}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.CONSENT_REQUIRED, result.networkState.mode)
        assertTrue(result.networkState.summary.contains("online refresh is awaiting startup consent"))
        assertTrue(result.networkState.usedCache)
        assertEquals(1, result.revokedCertificates.size)
        assertFalse(fetchCalled)
    }

    @Test
    fun `reports embedded snapshot parse error`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = false,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { true },
            feedFetcher = CrlFeedFetcher { """{"entries":{}}""" },
            embeddedStatusProvider = embeddedStatusProvider("""{"entries":"""),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ERROR, result.networkState.mode)
        assertTrue(result.networkState.summary.contains("Built-in CRL snapshot could not be parsed"))
    }
}
