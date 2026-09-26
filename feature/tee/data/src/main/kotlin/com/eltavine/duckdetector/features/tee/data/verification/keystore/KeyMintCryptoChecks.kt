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

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.eltavine.duckdetector.capability.attestation.data.AndroidKeyStoreTools
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.Mac

internal fun hmacSha256(useStrongBox: Boolean): KeyMintCheckResult {
    val keyStore = AndroidKeyStoreTools.loadKeyStore()
    val alias = "duck_keymint_hmac_${System.nanoTime()}"
    return runCatching {
        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_HMAC_SHA256,
            "AndroidKeyStore",
        )
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setKeySize(256)
            .setDigests(KeyProperties.DIGEST_SHA256)
        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        generator.init(builder.build())
        val key = generator.generateKey()
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(key)
        val output = mac.doFinal("duck_hmac_capability".encodeToByteArray())
        KeyMintCheckResult(output.size == 32, "HMAC-SHA256 output bytes=${output.size}.")
    }.getOrElse {
        KeyMintCheckResult(false, it.message ?: "HMAC-SHA256 generation failed.")
    }.also {
        AndroidKeyStoreTools.safeDelete(keyStore, alias)
    }
}

internal fun limitedUseEc(useStrongBox: Boolean): KeyMintCheckResult {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
        return KeyMintCheckResult(
            ok = true,
            detail = "Single-use EC requires Android 12 or newer.",
            executed = false,
        )
    }
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val alias = "duck_keymint_usage_${System.nanoTime()}"
    return runCatching {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore",
        )
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setMaxUsageCount(1)
        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        generator.initialize(builder.build())
        generator.generateKeyPair()
        val key = keyStore.getKey(alias, null) as PrivateKey
        val firstUseOk = sign(key, SIGNATURE_ECDSA_SHA256, "first")
        val secondUseOk = sign(key, SIGNATURE_ECDSA_SHA256, "second")
        KeyMintCheckResult(
            firstUseOk && !secondUseOk,
            "firstUse=$firstUseOk, secondUse=$secondUseOk.",
        )
    }.getOrElse {
        KeyMintCheckResult(false, it.message ?: "Single-use EC generation failed.")
    }.also {
        runCatching { keyStore.deleteEntry(alias) }
    }
}

internal fun ecdhP256(useStrongBox: Boolean): KeyMintCheckResult {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
        return KeyMintCheckResult(
            ok = true,
            detail = "ECDH requires Android 12 or newer.",
            executed = false,
        )
    }
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val alias = "duck_keymint_ecdh_${System.nanoTime()}"
    return runCatching {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore",
        )
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        generator.initialize(builder.build())
        val keyPair = generator.generateKeyPair()

        val peer = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val agreement = KeyAgreement.getInstance("ECDH", "AndroidKeyStore")
        agreement.init(keyPair.private)
        agreement.doPhase(peer.public, true)
        val secret = agreement.generateSecret()
        KeyMintCheckResult(secret.isNotEmpty(), "ECDH secret bytes=${secret.size}.")
    }.getOrElse {
        KeyMintCheckResult(false, it.message ?: "ECDH P-256 key agreement failed.")
    }.also {
        runCatching { keyStore.deleteEntry(alias) }
    }
}

internal fun rsaPssSha256(useStrongBox: Boolean): KeyMintCheckResult {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val alias = "duck_keymint_rsapss_${System.nanoTime()}"
    return runCatching {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            "AndroidKeyStore",
        )
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setKeySize(2048)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        generator.initialize(builder.build())
        val keyPair = generator.generateKeyPair()
        val message = "duck_rsapss_capability".encodeToByteArray()
        val signer = Signature.getInstance("SHA256withRSA/PSS")
        signer.initSign(keyPair.private)
        signer.update(message)
        val signature = signer.sign()

        val publicKey = KeyFactory.getInstance("RSA")
            .generatePublic(X509EncodedKeySpec(keyPair.public.encoded))
        val verifier = Signature.getInstance("SHA256withRSA/PSS")
        verifier.initVerify(publicKey)
        verifier.update(message)
        val verified = verifier.verify(signature)
        KeyMintCheckResult(verified, "signature bytes=${signature.size}, verified=$verified.")
    }.getOrElse {
        KeyMintCheckResult(false, it.message ?: "RSA-PSS SHA-256 signing failed.")
    }.also {
        runCatching { keyStore.deleteEntry(alias) }
    }
}

internal fun rsaOaepSha256RoundTrip(useStrongBox: Boolean): KeyMintCheckResult {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val alias = "duck_keymint_oaep_sha256_${System.nanoTime()}"
    return try {
        val keyPair = generateRsaKeyPair(alias, KeyProperties.PURPOSE_DECRYPT, useStrongBox) {
            setDigests(KeyProperties.DIGEST_SHA256)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
        }
        val payload = "duck_oaep_sha256".encodeToByteArray()
        val params = oaepSha256Mgf1Sha1()
        val encrypted = encrypt(rsaPublicKey(keyPair), CIPHER_RSA_OAEP_SHA256_MGF1, payload, params)
            ?: return KeyMintCheckResult(false, "RSA-OAEP SHA-256 encryption unavailable.")
        val decrypted = decrypt(keyPair.private, CIPHER_RSA_OAEP_SHA256_MGF1, encrypted, params)
        val roundTrip = decrypted?.contentEquals(payload) == true
        KeyMintCheckResult(roundTrip, "roundTrip=$roundTrip, decryptedBytes=${decrypted?.size ?: 0}.")
    } catch (throwable: Throwable) {
        KeyMintCheckResult(false, throwable.message ?: "RSA-OAEP SHA-256 round-trip failed.")
    } finally {
        runCatching { keyStore.deleteEntry(alias) }
    }
}
