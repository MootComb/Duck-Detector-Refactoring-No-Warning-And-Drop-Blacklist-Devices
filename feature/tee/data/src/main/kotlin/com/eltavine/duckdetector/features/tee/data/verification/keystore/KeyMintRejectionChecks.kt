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

import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.spec.IvParameterSpec

internal fun aesCbcCtrRejected(useStrongBox: Boolean): KeyMintCheckResult {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val alias = "duck_keymint_aesctr_${System.nanoTime()}"
    return try {
        val key = generateAesKey(alias, useStrongBox) {
            setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            setRandomizedEncryptionRequired(false)
        }
        val payload = "duck_aes_ctr".encodeToByteArray()
        val params = IvParameterSpec(ByteArray(16) { it.toByte() })
        val succeeded = encrypt(key, "AES/CTR/NoPadding", payload, params) != null
        KeyMintCheckResult(!succeeded, "unauthorizedEncryptSucceeded=$succeeded.")
    } catch (throwable: Throwable) {
        skipped("AES-CBC CTR authorization", throwable)
    } finally {
        runCatching { keyStore.deleteEntry(alias) }
    }
}

internal fun aesCbcNoPaddingRejected(useStrongBox: Boolean): KeyMintCheckResult {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val alias = "duck_keymint_aesnopad_${System.nanoTime()}"
    return try {
        val key = generateAesKey(alias, useStrongBox) {
            setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            setRandomizedEncryptionRequired(false)
        }
        val payload = ByteArray(16) { it.toByte() }
        val params = IvParameterSpec(ByteArray(16) { (it + 1).toByte() })
        val succeeded = encrypt(key, "AES/CBC/NoPadding", payload, params) != null
        KeyMintCheckResult(!succeeded, "unauthorizedEncryptSucceeded=$succeeded.")
    } catch (throwable: Throwable) {
        skipped("AES-CBC NoPadding authorization", throwable)
    } finally {
        runCatching { keyStore.deleteEntry(alias) }
    }
}

internal fun ecSha512Rejected(useStrongBox: Boolean): KeyMintCheckResult {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val alias = "duck_keymint_ecdigest_${System.nanoTime()}"
    return try {
        val keyPair = generateEcKeyPair(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            useStrongBox,
        )
        val succeeded = sign(keyPair.private, "SHA512withECDSA", "ec_sha512")
        KeyMintCheckResult(!succeeded, "unauthorizedSignSucceeded=$succeeded.")
    } catch (throwable: Throwable) {
        skipped("EC SHA-512 authorization", throwable)
    } finally {
        runCatching { keyStore.deleteEntry(alias) }
    }
}

internal fun rsaPssSha512Rejected(useStrongBox: Boolean): KeyMintCheckResult {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val alias = "duck_keymint_rsapssdigest_${System.nanoTime()}"
    return try {
        val keyPair = generateRsaKeyPair(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            useStrongBox,
        ) {
            setDigests(KeyProperties.DIGEST_SHA256)
            setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
        }
        val succeeded = sign(keyPair.private, "SHA512withRSA/PSS", "rsa_pss_sha512")
        KeyMintCheckResult(!succeeded, "unauthorizedSignSucceeded=$succeeded.")
    } catch (throwable: Throwable) {
        skipped("RSA-PSS SHA-512 authorization", throwable)
    } finally {
        runCatching { keyStore.deleteEntry(alias) }
    }
}

internal fun rsaPssPkcs1Rejected(useStrongBox: Boolean): KeyMintCheckResult {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val alias = "duck_keymint_rsapkcs1sig_${System.nanoTime()}"
    return try {
        val keyPair = generateRsaKeyPair(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            useStrongBox,
        ) {
            setDigests(KeyProperties.DIGEST_SHA256)
            setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
        }
        val succeeded = sign(keyPair.private, "SHA256withRSA", "rsa_pkcs1")
        KeyMintCheckResult(!succeeded, "unauthorizedSignSucceeded=$succeeded.")
    } catch (throwable: Throwable) {
        skipped("RSA-PSS PKCS#1 authorization", throwable)
    } finally {
        runCatching { keyStore.deleteEntry(alias) }
    }
}

internal fun rsaOaepPkcs1Rejected(useStrongBox: Boolean): KeyMintCheckResult {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val alias = "duck_keymint_rsapadding_${System.nanoTime()}"
    return try {
        val keyPair = generateRsaKeyPair(alias, KeyProperties.PURPOSE_DECRYPT, useStrongBox) {
            setDigests(KeyProperties.DIGEST_SHA256)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
        }
        val payload = "duck_rsa_padding".encodeToByteArray()
        val encrypted = encrypt(rsaPublicKey(keyPair), CIPHER_RSA_PKCS1, payload)
            ?: return KeyMintCheckResult(
                ok = true,
                detail = "RSA PKCS#1 encryption unavailable.",
                executed = false,
            )
        val succeeded = decrypt(keyPair.private, CIPHER_RSA_PKCS1, encrypted) != null
        KeyMintCheckResult(!succeeded, "unauthorizedDecryptSucceeded=$succeeded.")
    } catch (throwable: Throwable) {
        skipped("RSA-OAEP PKCS#1 authorization", throwable)
    } finally {
        runCatching { keyStore.deleteEntry(alias) }
    }
}

internal fun rsaPkcs1OaepRejected(useStrongBox: Boolean): KeyMintCheckResult {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val alias = "duck_keymint_rsaoaep_${System.nanoTime()}"
    return try {
        val keyPair = generateRsaKeyPair(alias, KeyProperties.PURPOSE_DECRYPT, useStrongBox) {
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
        }
        val payload = "duck_rsa_oaep_padding".encodeToByteArray()
        val encrypted = encrypt(rsaPublicKey(keyPair), CIPHER_RSA_OAEP_SHA1_MGF1, payload)
            ?: return KeyMintCheckResult(
                ok = true,
                detail = "RSA-OAEP SHA-1 encryption unavailable.",
                executed = false,
            )
        val succeeded = decrypt(keyPair.private, CIPHER_RSA_OAEP_SHA1_MGF1, encrypted) != null
        KeyMintCheckResult(!succeeded, "unauthorizedDecryptSucceeded=$succeeded.")
    } catch (throwable: Throwable) {
        skipped("RSA-PKCS#1 OAEP authorization", throwable)
    } finally {
        runCatching { keyStore.deleteEntry(alias) }
    }
}

internal fun rsaOaepSha1Rejected(useStrongBox: Boolean): KeyMintCheckResult {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val alias = "duck_keymint_oaep_sha1_${System.nanoTime()}"
    return try {
        val keyPair = generateRsaKeyPair(alias, KeyProperties.PURPOSE_DECRYPT, useStrongBox) {
            setDigests(KeyProperties.DIGEST_SHA256)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
        }
        val payload = "duck_oaep_sha1".encodeToByteArray()
        val encrypted = encrypt(rsaPublicKey(keyPair), CIPHER_RSA_OAEP_SHA1_MGF1, payload)
            ?: return KeyMintCheckResult(false, "RSA-OAEP SHA-1 encryption unavailable.")
        val succeeded = decrypt(keyPair.private, CIPHER_RSA_OAEP_SHA1_MGF1, encrypted) != null
        KeyMintCheckResult(!succeeded, "unauthorizedDecryptSucceeded=$succeeded.")
    } catch (throwable: Throwable) {
        KeyMintCheckResult(false, throwable.message ?: "RSA-OAEP SHA-1 rejection probe failed.")
    } finally {
        runCatching { keyStore.deleteEntry(alias) }
    }
}

internal fun ecNoneRejected(useStrongBox: Boolean): KeyMintCheckResult {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val alias = "duck_keymint_ecnone_${System.nanoTime()}"
    return try {
        val keyPair = generateEcKeyPair(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            useStrongBox,
        )
        val succeeded = sign(keyPair.private, "NONEwithECDSA", "ec_none")
        KeyMintCheckResult(!succeeded, "unauthorizedSignSucceeded=$succeeded.")
    } catch (throwable: Throwable) {
        KeyMintCheckResult(false, throwable.message ?: "EC NONE digest probe failed.")
    } finally {
        runCatching { keyStore.deleteEntry(alias) }
    }
}

internal fun rsaPkcs1Sha1Rejected(useStrongBox: Boolean): KeyMintCheckResult {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val alias = "duck_keymint_rsapkcs1sha1_${System.nanoTime()}"
    return try {
        val keyPair = generateRsaKeyPair(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            useStrongBox,
        ) {
            setDigests(KeyProperties.DIGEST_SHA256)
            setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
        }
        val succeeded = sign(keyPair.private, "SHA1withRSA", "rsa_pkcs1_sha1")
        KeyMintCheckResult(!succeeded, "unauthorizedSignSucceeded=$succeeded.")
    } catch (throwable: Throwable) {
        KeyMintCheckResult(false, throwable.message ?: "RSA PKCS#1 SHA-1 probe failed.")
    } finally {
        runCatching { keyStore.deleteEntry(alias) }
    }
}

internal fun rsaPkcs1PssRejected(useStrongBox: Boolean): KeyMintCheckResult {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val alias = "duck_keymint_rsapkcs1pss_${System.nanoTime()}"
    return try {
        val keyPair = generateRsaKeyPair(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            useStrongBox,
        ) {
            setDigests(KeyProperties.DIGEST_SHA256)
            setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
        }
        val succeeded = sign(keyPair.private, "SHA256withRSA/PSS", "rsa_pkcs1_pss")
        KeyMintCheckResult(!succeeded, "unauthorizedSignSucceeded=$succeeded.")
    } catch (throwable: Throwable) {
        KeyMintCheckResult(false, throwable.message ?: "RSA PKCS#1/PSS probe failed.")
    } finally {
        runCatching { keyStore.deleteEntry(alias) }
    }
}
