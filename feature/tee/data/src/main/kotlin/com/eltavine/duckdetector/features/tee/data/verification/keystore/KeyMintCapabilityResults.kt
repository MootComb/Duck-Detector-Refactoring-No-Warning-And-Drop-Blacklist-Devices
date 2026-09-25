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

data class KeyMintCapabilityResult(
    val executed: Boolean,
    val crypto: KeyMintCryptoCapabilityResult = KeyMintCryptoCapabilityResult(),
    val diagnosticCopyText: String = "",
)

data class KeyMintCryptoCapabilityResult(
    val hmacSha256Ok: Boolean = true,
    val hmacSha256Detail: String = "HMAC-SHA256 skipped.",
    val limitedUseEcExecuted: Boolean = true,
    val limitedUseEcOk: Boolean = true,
    val limitedUseEcDetail: String = "Single-use EC skipped.",
    val ecdhP256Executed: Boolean = true,
    val ecdhP256Ok: Boolean = true,
    val ecdhP256Detail: String = "ECDH P-256 skipped.",
    val rsaPssSha256Ok: Boolean = true,
    val rsaPssSha256Detail: String = "RSA-PSS SHA-256 skipped.",
    val aesCbcCtrExecuted: Boolean = true,
    val aesCbcCtrOk: Boolean = true,
    val aesCbcCtrDetail: String = "AES-CBC CTR authorization skipped.",
    val aesCbcNoPaddingExecuted: Boolean = true,
    val aesCbcNoPaddingOk: Boolean = true,
    val aesCbcNoPaddingDetail: String = "AES-CBC NoPadding authorization skipped.",
    val ecSha512Executed: Boolean = true,
    val ecSha512Ok: Boolean = true,
    val ecSha512Detail: String = "EC SHA-512 authorization skipped.",
    val rsaPssSha512Executed: Boolean = true,
    val rsaPssSha512Ok: Boolean = true,
    val rsaPssSha512Detail: String = "RSA-PSS SHA-512 authorization skipped.",
    val rsaPssPkcs1Executed: Boolean = true,
    val rsaPssPkcs1Ok: Boolean = true,
    val rsaPssPkcs1Detail: String = "RSA-PSS PKCS#1 authorization skipped.",
    val rsaOaepPkcs1Executed: Boolean = true,
    val rsaOaepPkcs1Ok: Boolean = true,
    val rsaOaepPkcs1Detail: String = "RSA-OAEP PKCS#1 authorization skipped.",
    val rsaPkcs1OaepExecuted: Boolean = true,
    val rsaPkcs1OaepOk: Boolean = true,
    val rsaPkcs1OaepDetail: String = "RSA-PKCS#1 OAEP authorization skipped.",
    val rsaOaepMgf1Executed: Boolean = true,
    val rsaOaepMgf1Ok: Boolean = true,
    val rsaOaepMgf1Detail: String = "RSA-OAEP MGF1 skipped.",
    val rsaOaepMgf1Sha1Executed: Boolean = true,
    val rsaOaepMgf1Sha1Ok: Boolean = true,
    val rsaOaepMgf1Sha1Detail: String = "RSA-OAEP MGF1 SHA-1 authorization skipped.",
    val rsaOaepSha256Executed: Boolean = true,
    val rsaOaepSha256Ok: Boolean = true,
    val rsaOaepSha256Detail: String = "RSA-OAEP SHA-256 skipped.",
    val rsaOaepSha1Executed: Boolean = true,
    val rsaOaepSha1Ok: Boolean = true,
    val rsaOaepSha1Detail: String = "RSA-OAEP SHA-1 authorization skipped.",
    val ecNoneExecuted: Boolean = true,
    val ecNoneOk: Boolean = true,
    val ecNoneDetail: String = "EC NONE digest authorization skipped.",
    val rsaPkcs1Sha1Executed: Boolean = true,
    val rsaPkcs1Sha1Ok: Boolean = true,
    val rsaPkcs1Sha1Detail: String = "RSA PKCS#1 SHA-1 authorization skipped.",
    val rsaPkcs1PssExecuted: Boolean = true,
    val rsaPkcs1PssOk: Boolean = true,
    val rsaPkcs1PssDetail: String = "RSA PKCS#1/PSS authorization skipped.",
    val grantUpdateSubcomponentExecuted: Boolean = true,
    val grantUpdateSubcomponentOk: Boolean = true,
    val grantUpdateSubcomponentDetail: String = "Grant updateSubcomponent skipped.",
)
