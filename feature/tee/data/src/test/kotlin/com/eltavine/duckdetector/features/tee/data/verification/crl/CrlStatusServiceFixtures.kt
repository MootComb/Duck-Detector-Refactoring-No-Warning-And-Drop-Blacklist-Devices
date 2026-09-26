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
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefsStore
import java.math.BigInteger
import java.security.Principal
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow

internal class FakeTeeNetworkPrefsStore(
    initial: TeeNetworkPrefs,
) : TeeNetworkPrefsStore {
    private val state = MutableStateFlow(initial)

    override val prefs: Flow<TeeNetworkPrefs> = state

    val current: TeeNetworkPrefs
        get() = state.value

    override suspend fun setConsent(granted: Boolean) {
        state.value = state.value.copy(
            consentAsked = true,
            consentGranted = granted,
            crlCacheJson = null,
            crlFetchedAt = 0L,
        )
    }

    override suspend fun storeCrlCache(json: String?, fetchedAt: Long) {
        state.value = state.value.copy(
            crlCacheJson = json,
            crlFetchedAt = fetchedAt,
        )
    }

    override suspend fun clearCache() {
        state.value = state.value.copy(
            crlCacheJson = null,
            crlFetchedAt = 0L,
        )
    }
}

internal fun embeddedStatusProvider(json: String): CrlEmbeddedStatusProvider {
    return CrlEmbeddedStatusProvider { json }
}

@Suppress("DEPRECATION")
internal class FakeX509Certificate(
    private val serialHex: String,
) : X509Certificate() {

    override fun getSerialNumber(): BigInteger = BigInteger(serialHex, 16)

    override fun getEncoded(): ByteArray = ByteArray(0)

    override fun verify(key: PublicKey?) = Unit

    override fun verify(key: PublicKey?, sigProvider: String?) = Unit

    override fun toString(): String = "FakeX509Certificate($serialHex)"

    override fun getPublicKey(): PublicKey {
        throw UnsupportedOperationException()
    }

    override fun checkValidity() = Unit

    override fun checkValidity(date: Date?) = Unit

    override fun getVersion(): Int = 3

    override fun getIssuerDN(): Principal = X500Principal("CN=issuer")

    override fun getSubjectDN(): Principal = X500Principal("CN=subject")

    override fun getNotBefore(): Date = Date(0L)

    override fun getNotAfter(): Date = Date(0L)

    override fun getTBSCertificate(): ByteArray = ByteArray(0)

    override fun getSignature(): ByteArray = ByteArray(0)

    override fun getSigAlgName(): String = "NONE"

    override fun getSigAlgOID(): String = "1.2.3"

    override fun getSigAlgParams(): ByteArray = ByteArray(0)

    override fun getIssuerUniqueID(): BooleanArray? = null

    override fun getSubjectUniqueID(): BooleanArray? = null

    override fun getKeyUsage(): BooleanArray? = null

    override fun getBasicConstraints(): Int = -1

    override fun getCriticalExtensionOIDs(): MutableSet<String>? = null

    override fun getExtensionValue(oid: String?): ByteArray? = null

    override fun getNonCriticalExtensionOIDs(): MutableSet<String>? = null

    override fun hasUnsupportedCriticalExtension(): Boolean = false

    override fun getExtendedKeyUsage(): MutableList<String>? = null

    override fun getSubjectAlternativeNames(): MutableCollection<MutableList<*>>? = null

    override fun getIssuerAlternativeNames(): MutableCollection<MutableList<*>>? = null

    override fun getSubjectX500Principal(): X500Principal = X500Principal("CN=subject")

    override fun getIssuerX500Principal(): X500Principal = X500Principal("CN=issuer")
}

internal const val NOW = 1_900_000_000_000L

internal const val LOCAL_MASS_ABUSE_SERIAL = "8616ef30679ed43cc2b43e3c97a2319e"

internal const val LOCAL_MASS_ABUSE_SERIAL_DEC =
    "178235633296982535164483918324719301022"
