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

import com.eltavine.duckdetector.capability.attestation.data.AndroidKeyStoreTools
import java.security.KeyStore
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import kotlin.math.roundToInt

class KeyPairConsistencyProbe {

    fun inspect(
        keyStore: KeyStore = AndroidKeyStoreTools.loadKeyStore(),
        useStrongBox: Boolean = false,
    ): KeyPairConsistencyResult {
        val alias = "duck_pair_consistency_${System.nanoTime()}"
        val subject = "CN=DuckDetector Pair Probe, O=Eltavine"
        return runCatching {
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias,
                subject = subject,
                useStrongBox = useStrongBox,
            )
            val privateKey = AndroidKeyStoreTools.readPrivateKey(keyStore, alias)
            val certificate = AndroidKeyStoreTools.readLeafCertificate(keyStore, alias)
            if (privateKey == null || certificate == null) {
                return KeyPairConsistencyResult(
                    keyMatchesCertificate = false,
                    detail = "Missing private key or certificate after key generation.",
                )
            }
            val payload = "duck_pair_probe".encodeToByteArray()
            val signature = AndroidKeyStoreTools.signData(privateKey, payload)
            val verified = verifySignature(certificate, payload, signature)
            val timings = runCatching { sampleSigningMicros(privateKey) }.getOrDefault(TimingStats())
            KeyPairConsistencyResult(
                keyMatchesCertificate = verified,
                medianSignMicros = timings.medianMicros,
                jitterRatio = timings.jitterRatio,
                detail = if (verified) {
                    "Leaf certificate public key validates fresh signatures."
                } else {
                    "Leaf certificate public key failed to verify locally signed data."
                },
            )
        }.getOrElse { throwable ->
            val reason = throwable.message ?: "Key pair consistency probe did not complete."
            KeyPairConsistencyResult(
                executed = false,
                keyMatchesCertificate = false,
                probeError = reason,
                detail = reason,
            )
        }.also {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
    }

    /** Local JCA work on what keystore returned, so a key or signature it cannot parse does not verify. */
    private fun verifySignature(
        certificate: X509Certificate,
        payload: ByteArray,
        signatureBytes: ByteArray,
    ): Boolean = runCatching {
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(certificate.publicKey)
        verifier.update(payload)
        verifier.verify(signatureBytes)
    }.getOrDefault(false)

    private fun sampleSigningMicros(privateKey: java.security.PrivateKey): TimingStats {
        val samples = buildList {
            repeat(6) {
                val signer = Signature.getInstance("SHA256withECDSA")
                val payload = "duck_pair_timing_$it".encodeToByteArray()
                val start = System.nanoTime()
                signer.initSign(privateKey)
                signer.update(payload)
                signer.sign()
                val elapsedMicros = (System.nanoTime() - start) / 1_000.0
                add(elapsedMicros)
            }
        }.sorted()
        if (samples.isEmpty()) {
            return TimingStats()
        }
        val min = samples.first()
        val max = samples.last()
        val median = samples[samples.size / 2]
        val jitter = if (min > 0.0) (max - min) / min else 0.0
        return TimingStats(
            medianMicros = median.roundToInt(),
            jitterRatio = jitter,
        )
    }
}

/**
 * Keystore2 prunes a caller's own sibling operations when KeyMint runs out of operation slots
 * (system/security keystore2/src/operation.rs), and this probe signs while other keystore probes,
 * including the one that saturates operation slots, run in parallel. So a keystore exception means
 * the probe did not complete; only a signature that fails local verification is a mismatch.
 */
data class KeyPairConsistencyResult(
    val executed: Boolean = true,
    val keyMatchesCertificate: Boolean,
    val probeError: String? = null,
    val medianSignMicros: Int? = null,
    val jitterRatio: Double? = null,
    val detail: String,
)

private data class TimingStats(
    val medianMicros: Int? = null,
    val jitterRatio: Double? = null,
)
