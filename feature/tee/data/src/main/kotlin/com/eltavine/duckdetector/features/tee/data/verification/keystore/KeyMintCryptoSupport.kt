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
import java.math.BigInteger
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Calendar
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.security.auth.x500.X500Principal

internal fun sign(key: PrivateKey, algorithm: String, label: String): Boolean = runCatching {
    val signer = Signature.getInstance(algorithm)
    signer.initSign(key)
    signer.update("duck_usage_$label".encodeToByteArray())
    signer.sign()
    true
}.getOrDefault(false)

internal fun generateEcKeyPair(
    alias: String,
    purposes: Int,
    useStrongBox: Boolean,
    configure: KeyGenParameterSpec.Builder.() -> Unit = {},
): KeyPair {
    val generator = KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_EC,
        "AndroidKeyStore",
    )
    val builder = KeyGenParameterSpec.Builder(alias, purposes)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setCertificateSubject(X500Principal("CN=DuckDetector KeyMint Probe, O=Eltavine"))
        .setCertificateSerialNumber(BigInteger.valueOf(System.nanoTime()))
        .setCertificateNotBefore(Calendar.getInstance().time)
        .setCertificateNotAfter(Calendar.getInstance().apply { add(Calendar.YEAR, 1) }.time)
        .setAttestationChallenge("duck_keymint_probe".encodeToByteArray())
        .setDigests(KeyProperties.DIGEST_SHA256)
    builder.configure()
    applyStrongBox(builder, useStrongBox)
    generator.initialize(builder.build())
    return generator.generateKeyPair()
}

internal fun generateRsaKeyPair(
    alias: String,
    purposes: Int,
    useStrongBox: Boolean,
    configure: KeyGenParameterSpec.Builder.() -> Unit,
): KeyPair {
    val generator = KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_RSA,
        "AndroidKeyStore",
    )
    val builder = KeyGenParameterSpec.Builder(alias, purposes).setKeySize(2048)
        .setCertificateSubject(X500Principal("CN=DuckDetector KeyMint Probe, O=Eltavine"))
        .setCertificateSerialNumber(BigInteger.valueOf(System.nanoTime()))
        .setCertificateNotBefore(Calendar.getInstance().time)
        .setCertificateNotAfter(Calendar.getInstance().apply { add(Calendar.YEAR, 1) }.time)
        .setAttestationChallenge("duck_keymint_probe".encodeToByteArray())
    builder.configure()
    applyStrongBox(builder, useStrongBox)
    generator.initialize(builder.build())
    return generator.generateKeyPair()
}

internal fun generateAesKey(
    alias: String,
    useStrongBox: Boolean,
    configure: KeyGenParameterSpec.Builder.() -> Unit,
): SecretKey {
    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    val builder = KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
    ).setKeySize(128)
    builder.configure()
    applyStrongBox(builder, useStrongBox)
    generator.init(builder.build())
    return generator.generateKey()
}

private fun applyStrongBox(builder: KeyGenParameterSpec.Builder, useStrongBox: Boolean) {
    if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        builder.setIsStrongBoxBacked(true)
    }
}

internal fun rsaPublicKey(keyPair: KeyPair): PublicKey =
    KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(keyPair.public.encoded))

internal fun encrypt(
    key: Key,
    transform: String,
    payload: ByteArray,
    params: AlgorithmParameterSpec? = null,
): ByteArray? = runCatching {
    Cipher.getInstance(transform).apply {
        if (params == null) init(Cipher.ENCRYPT_MODE, key) else init(Cipher.ENCRYPT_MODE, key, params)
    }.doFinal(payload)
}.getOrNull()

internal fun decrypt(
    key: PrivateKey,
    transform: String,
    payload: ByteArray,
    params: AlgorithmParameterSpec? = null,
): ByteArray? = runCatching {
    Cipher.getInstance(transform).apply {
        if (params == null) init(Cipher.DECRYPT_MODE, key) else init(Cipher.DECRYPT_MODE, key, params)
    }.doFinal(payload)
}.getOrNull()

internal fun oaepSha256Mgf1Sha256(): OAEPParameterSpec =
    OAEPParameterSpec(
        "SHA-256",
        "MGF1",
        MGF1ParameterSpec.SHA256,
        PSource.PSpecified.DEFAULT,
    )

internal fun oaepSha256Mgf1Sha1(): OAEPParameterSpec =
    OAEPParameterSpec(
        "SHA-256",
        "MGF1",
        MGF1ParameterSpec.SHA1,
        PSource.PSpecified.DEFAULT,
    )

internal fun skipped(name: String, throwable: Throwable): KeyMintCheckResult =
    KeyMintCheckResult(
        ok = true,
        detail = "${throwable.message ?: "$name unavailable."}",
        executed = false,
    )

internal data class KeyMintCheckResult(
    val ok: Boolean,
    val detail: String,
    val executed: Boolean = true,
    val diagnostic: String? = null,
)
