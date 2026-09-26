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

import android.content.Context
import android.os.Build
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import androidx.annotation.ChecksSdkIntAtLeast
import com.eltavine.duckdetector.capability.attestation.data.AndroidKeyStoreTools
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ImportKeyRetainedAttestationNarrativeProbe.ImportSupportResult
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ImportKeyRetainedAttestationNarrativeProbe.PostImportMetadata
import com.eltavine.duckdetector.features.tee.data.verification.keystore.ImportKeyRetainedAttestationNarrativeProbe.Runtime
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

internal class ImportKeyAndroidRuntime(
    context: Context,
    private val binderClient: Keystore2PrivateBinderClient,
) : Runtime {
    private val appContext = context.applicationContext
    private val certificateFactory = CertificateFactory.getInstance("X.509")
    private val keyStore = AndroidKeyStoreTools.loadKeyStore()

    @get:ChecksSdkIntAtLeast(api = Build.VERSION_CODES.S)
    override val supported: Boolean
        get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

    override val importedOriginValues: Set<Int>
        get() = setOfNotNull(
            binderClient.getKeyOriginValue("IMPORTED"),
            binderClient.getKeyOriginValue("SECURELY_IMPORTED"),
            ORIGIN_IMPORTED_FALLBACK,
            ORIGIN_SECURELY_IMPORTED_FALLBACK,
        )

    override val generatedOriginValue: Int?
        get() = binderClient.getKeyOriginValue("GENERATED") ?: ORIGIN_GENERATED_FALLBACK

    override fun generatePriorAttestedChain(alias: String, challenge: ByteArray): List<ByteArray> {
        AndroidKeyStoreTools.generateSigningEcKey(
            keyStore = keyStore,
            alias = alias,
            subject = "CN=DuckDetector ImportKey Retained, O=Eltavine",
            useStrongBox = false,
            challenge = challenge,
        )
        return AndroidKeyStoreTools.readCertificateChain(keyStore, alias)
            .map(X509Certificate::getEncoded)
    }

    override fun importMarkerKey(alias: String) {
        val fixture = KeyboxFixtureLoader(appContext).load()
        val protection = KeyProtection.Builder(
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .build()
        keyStore.setEntry(
            alias,
            java.security.KeyStore.PrivateKeyEntry(fixture.privateKey, arrayOf(fixture.certificate)),
            protection,
        )
    }

    override fun verifyImportSupport(alias: String): ImportSupportResult {
        importMarkerKey(alias)
        val metadata = readPostImportMetadata(alias)
        val originImported = metadata?.originValue in importedOriginValues
        val leafMatchesMarker = metadata?.leafMatchesMarker == true
        val supported = originImported && leafMatchesMarker
        return ImportSupportResult(
            supported = supported,
            leafMatchesMarker = leafMatchesMarker,
            originValue = metadata?.originValue,
            originLabel = originLabel(metadata?.originValue),
            detail = if (supported) {
                "origin=${originLabel(metadata.originValue)}, marker import baseline clean."
            } else {
                "ImportKey support gate failed: origin=${originLabel(metadata?.originValue)}, leafMatchesMarker=$leafMatchesMarker."
            },
        )
    }

    override fun readPostImportMetadataSnapshots(alias: String): List<PostImportMetadata> {
        return listOfNotNull(
            readPostImportMetadata(alias),
            readPostImportMetadata(alias),
        )
    }

    private fun readPostImportMetadata(alias: String): PostImportMetadata? {
        val service = binderClient.getKeystoreService() ?: return null
        val response = binderClient.getKeyEntryResponse(service, binderClient.createKeyDescriptor(alias))
            ?: return null
        val metadata = binderClient.getMetadata(response) ?: return null
        val originTag = binderClient.getTagValue("ORIGIN")
        val originValue = originTag?.let { tag ->
            binderClient.getMetadataAuthorizations(metadata)
                .firstOrNull { authorization ->
                    authorization?.let(binderClient::getAuthorizationTag) == tag
                }
                ?.let { authorization -> binderClient.getAuthorizationIntValue(authorization) }
        }
        val markerLeaf = KeyboxFixtureLoader(appContext).load().certificate.encoded
        val leafBlob = binderClient.getCertificateBlob(response)
        val chainBlob = binderClient.getCertificateChainBlob(response)
        return PostImportMetadata(
            originValue = originValue,
            // Keystore2 stores the leaf separately from the remaining chain; compare the ordered full narrative, not only certificateChain.
            // Keystore2 会把叶证书和剩余链分开放；这里必须比较有序完整叙事，而不是只比较 certificateChain。
            fullChain = buildFullChain(leafBlob, chainBlob),
            leafMatchesMarker = leafBlob?.contentEquals(markerLeaf) == true,
        )
    }

    override fun cleanup(alias: String) {
        AndroidKeyStoreTools.safeDelete(keyStore, alias)
    }

    override fun originLabel(value: Int?): String {
        return when (value) {
            null -> "unknown"
            binderClient.getKeyOriginValue("GENERATED") -> "GENERATED"
            binderClient.getKeyOriginValue("DERIVED") -> "DERIVED"
            binderClient.getKeyOriginValue("IMPORTED") -> "IMPORTED"
            binderClient.getKeyOriginValue("UNKNOWN") -> "UNKNOWN"
            binderClient.getKeyOriginValue("SECURELY_IMPORTED") -> "SECURELY_IMPORTED"
            else -> value.toString()
        }
    }

    override fun describeThrowable(throwable: Throwable): String {
        return binderClient.describeThrowable(throwable)
    }

    private fun buildFullChain(leafBlob: ByteArray?, chainBlob: ByteArray?): List<ByteArray> {
        return listOfNotNull(leafBlob?.takeIf { it.isNotEmpty() }) + parseCertificates(chainBlob)
    }

    private fun parseCertificates(blob: ByteArray?): List<ByteArray> {
        if (blob == null || blob.isEmpty()) {
            return emptyList()
        }
        return runCatching {
            certificateFactory.generateCertificates(ByteArrayInputStream(blob))
                .filterIsInstance<X509Certificate>()
                .map(X509Certificate::getEncoded)
        }.getOrDefault(emptyList())
    }
}

internal const val ORIGIN_GENERATED_FALLBACK = 0

internal const val ORIGIN_IMPORTED_FALLBACK = 2

internal const val ORIGIN_SECURELY_IMPORTED_FALLBACK = 4
