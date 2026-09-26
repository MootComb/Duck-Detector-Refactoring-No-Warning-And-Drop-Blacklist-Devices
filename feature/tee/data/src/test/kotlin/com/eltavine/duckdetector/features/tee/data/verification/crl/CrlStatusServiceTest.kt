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
import java.io.IOException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CrlStatusServiceTest {

    @Test
    fun `refreshes online revocation data without caching it`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )
        var fetchCount = 0
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { true },
            feedFetcher = CrlFeedFetcher {
                fetchCount += 1
                """{"entries":{"1":{"status":"REVOKED","reason":"keyCompromise"}}}"""
            },
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ACTIVE, result.networkState.mode)
        assertFalse(result.networkState.usedCache)
        assertEquals(1, fetchCount)
        assertEquals(1, result.revokedCertificates.size)
        assertTrue(result.networkState.summary.contains("matched 1 revoked/suspended entry"))
        assertEquals(null, store.current.crlCacheJson)
    }

    @Test
    fun `uses built in revocation snapshot when online refresh is disabled`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
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
                ""
            },
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{"1":{"status":"REVOKED","reason":"embedded"}}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.SKIPPED, result.networkState.mode)
        assertTrue(result.networkState.summary.contains("online refresh is disabled in Settings"))
        assertTrue(result.networkState.usedCache)
        assertEquals(1, result.revokedCertificates.size)
        assertFalse(fetchCalled)
    }

    @Test
    fun `falls back to built in snapshot when online refresh fails`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )
        var fetchCount = 0
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { false },
            feedFetcher = CrlFeedFetcher {
                fetchCount += 1
                throw IOException("offline")
            },
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{"1":{"status":"REVOKED","reason":"embedded"}}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ERROR, result.networkState.mode)
        assertEquals(1, fetchCount)
        assertTrue(result.networkState.summary.contains("built-in revocation snapshot was used"))
        assertTrue(result.networkState.detail.orEmpty().contains("ConnectivityManager"))
        assertTrue(result.networkState.usedCache)
        assertTrue(result.networkState.usingCacheFallback)
        assertEquals(1, result.revokedCertificates.size)
    }

    @Test
    fun `online refresh does not downgrade built in revocations`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )
        var fetchCount = 0
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { false },
            feedFetcher = CrlFeedFetcher {
                fetchCount += 1
                """{"entries":{"1":{"status":"GOOD"}}}"""
            },
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{"1":{"status":"REVOKED","reason":"embedded"}}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ACTIVE, result.networkState.mode)
        assertEquals(1, fetchCount)
        assertTrue(result.networkState.summary.contains("matched 1 revoked/suspended entry"))
        assertTrue(
            result.networkState.detail.orEmpty().contains("Direct HTTPS fetch still succeeded")
        )
        assertEquals(1, result.revokedCertificates.size)
        assertEquals("embedded", result.revokedCertificates.single().reason)
    }

    @Test
    fun `local hardcoded abuse serial is classified as mass abuse warning evidence`() = runBlocking {
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
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{"8616ef30679ed43cc2b43e3c97a2319e":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate(LOCAL_MASS_ABUSE_SERIAL)))

        assertEquals(1, result.revokedCertificates.size)
        assertEquals("MASS_ABUSE", result.revokedCertificates.single().reason)
        assertEquals(
            RevokedCertificateEvidenceKind.LOCAL_MASS_ABUSE,
            result.revokedCertificates.single().evidenceKind,
        )
    }

    @Test
    fun `online hardcoded abuse serial remains standard revocation evidence`() = runBlocking {
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
            feedFetcher = CrlFeedFetcher {
                """{"entries":{"8616ef30679ed43cc2b43e3c97a2319e":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}"""
            },
            embeddedStatusProvider = embeddedStatusProvider("""{"entries":{}}"""),
        )

        val result = service.inspect(listOf(FakeX509Certificate(LOCAL_MASS_ABUSE_SERIAL)))

        assertEquals(1, result.revokedCertificates.size)
        assertEquals("KEY_COMPROMISE", result.revokedCertificates.single().reason)
        assertEquals(
            RevokedCertificateEvidenceKind.STANDARD_REVOCATION,
            result.revokedCertificates.single().evidenceKind,
        )
    }

    @Test
    fun `online decimal hardcoded abuse serial overrides local hex warning evidence`() = runBlocking {
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
            feedFetcher = CrlFeedFetcher {
                """{"entries":{"${LOCAL_MASS_ABUSE_SERIAL_DEC}":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}"""
            },
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{"8616ef30679ed43cc2b43e3c97a2319e":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate(LOCAL_MASS_ABUSE_SERIAL)))

        assertEquals(1, result.revokedCertificates.size)
        assertEquals("KEY_COMPROMISE", result.revokedCertificates.single().reason)
        assertEquals(
            RevokedCertificateEvidenceKind.STANDARD_REVOCATION,
            result.revokedCertificates.single().evidenceKind,
        )
    }

    @Test
    fun `online good status does not suppress local mass abuse warning evidence`() = runBlocking {
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
            feedFetcher = CrlFeedFetcher {
                """{"entries":{"8616ef30679ed43cc2b43e3c97a2319e":{"status":"GOOD"}}}"""
            },
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{"8616ef30679ed43cc2b43e3c97a2319e":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate(LOCAL_MASS_ABUSE_SERIAL)))

        assertEquals(1, result.revokedCertificates.size)
        assertEquals("MASS_ABUSE", result.revokedCertificates.single().reason)
        assertEquals(
            RevokedCertificateEvidenceKind.LOCAL_MASS_ABUSE,
            result.revokedCertificates.single().evidenceKind,
        )
    }

    @Test
    fun `matches revoked certificate when feed key is decimal`() = runBlocking {
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
            feedFetcher = CrlFeedFetcher {
                """{"entries":{"26":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}"""
            },
            embeddedStatusProvider = embeddedStatusProvider("""{"entries":{}}"""),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1a")))

        assertEquals(TeeNetworkMode.ACTIVE, result.networkState.mode)
        assertEquals(1, result.revokedCertificates.size)
        assertTrue(result.revokedCertificates.single().serial.contains("1a / 26"))
        assertTrue(result.networkState.summary.contains("matched 1 revoked/suspended entry"))
    }
}
