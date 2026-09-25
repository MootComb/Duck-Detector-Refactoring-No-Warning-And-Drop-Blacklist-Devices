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
import java.io.ByteArrayInputStream
import java.security.PublicKey
import java.security.cert.CertificateFactory

internal class RawRsaOaepMgf1Checks(
    private val binderClient: Keystore2PrivateBinderClient,
) {

    fun rsaOaepMgf1Sha256(
        backend: KeyMintBackendDecision,
        securityLevelsConsistent: Boolean,
        useStrongBox: Boolean,
    ): KeyMintCheckResult {
        val plan = resolveMgf1ProbePlan(backend, securityLevelsConsistent)
        if (plan.mode == Mgf1ProbeMode.SKIP) {
            return KeyMintCheckResult(
                ok = true,
                detail = plan.detail,
                executed = false,
            )
        }
        // We intentionally do not trust UI/API level alone here.
        // AndroidKeyStore only exposes MGF-digest configuration from newer framework APIs, but the
        // detection target is the backend KeyMint behavior, not the Java wrapper surface.
        // 因此这里不能只看 API level 或 Java API 是否暴露 setMgf1Digests；我们真正要验证的是
        // 后端 KeyMint/keystore2 的行为，而不是 framework 包装层是否恰好提供了公开入口。
        //
        // AOSP references:
        // frameworks/base/keystore/java/android/security/keystore2/AndroidKeyStoreRSACipherSpi.java
        // https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/keystore/java/android/security/keystore2/AndroidKeyStoreRSACipherSpi.java
        // hardware/interfaces/security/keymint/aidl/vts/functional/KeyMintTest.cpp
        // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/keymint/aidl/vts/functional/KeyMintTest.cpp
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return KeyMintCheckResult(
                ok = true,
                detail = "RSA-OAEP MGF1 digest probe requires a native KeyMint 1+ backend.",
                executed = false,
            )
        }
        val alias = "duck_keymint_rsamgf_${System.nanoTime()}"
        return withRawRsaOaepKey(
            alias = alias,
            useStrongBox = useStrongBox,
            generationName = "Raw keystore2 RSA-OAEP key generation",
            probeName = "RSA-OAEP MGF1 SHA-256",
        ) { rawKey ->
            val capability = evaluateRsaOaepMgf1Capability(
                authorizations = rawKey.authorizations,
                attestationVersion = backend.attestationVersion,
                keymasterVersion = backend.keymasterVersion,
                declaredKeyMintVersion = backend.version,
                expectedSecurityLevel = rawKey.expectedSecurityLevel,
                returnedSecurityLevel = rawKey.returnedSecurityLevel,
                probeMode = plan.mode,
            )
            if (!capability.shouldExecute) {
                KeyMintCheckResult(
                    ok = true,
                    detail = capability.detail,
                    executed = false,
                    diagnostic = capability.diagnostic,
                )
            } else if (!capability.supported) {
                KeyMintCheckResult(ok = false, detail = capability.detail, diagnostic = capability.diagnostic)
            } else {
                val payload = "duck_rsa_oaep_mgf1".encodeToByteArray()
                val params = oaepSha256Mgf1Sha256()
                val encrypted = encrypt(
                    rawKey.publicKey,
                    CIPHER_RSA_OAEP_SHA256_MGF1,
                    payload,
                    params,
                )
                if (encrypted == null) {
                    KeyMintCheckResult(false, "RSA-OAEP SHA-256 local encryption failed.")
                } else {
                    rawRsaOaepMgf1RoundTrip(rawKey, encrypted, payload)
                }
            }
        }
    }

    fun rsaOaepMgf1Sha1Rejected(
        backend: KeyMintBackendDecision,
        securityLevelsConsistent: Boolean,
        useStrongBox: Boolean,
    ): KeyMintCheckResult {
        val plan = resolveMgf1ProbePlan(backend, securityLevelsConsistent)
        if (plan.mode == Mgf1ProbeMode.SKIP) {
            return KeyMintCheckResult(
                ok = true,
                detail = plan.detail,
                executed = false,
            )
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return KeyMintCheckResult(
                ok = true,
                detail = "RSA-OAEP MGF1 authorization probe requires a native KeyMint 1+ backend.",
                executed = false,
            )
        }
        val alias = "duck_keymint_rsamgfsha1_${System.nanoTime()}"
        return withRawRsaOaepKey(
            alias = alias,
            useStrongBox = useStrongBox,
            generationName = "Raw keystore2 RSA-OAEP authorization key generation",
            probeName = "RSA-OAEP MGF1 authorization",
        ) { rawKey ->
            val capability = evaluateRsaOaepMgf1Capability(
                authorizations = rawKey.authorizations,
                attestationVersion = backend.attestationVersion,
                keymasterVersion = backend.keymasterVersion,
                declaredKeyMintVersion = backend.version,
                expectedSecurityLevel = rawKey.expectedSecurityLevel,
                returnedSecurityLevel = rawKey.returnedSecurityLevel,
                probeMode = plan.mode,
            )
            if (!capability.shouldExecute) {
                KeyMintCheckResult(
                    ok = true,
                    detail = capability.detail,
                    executed = false,
                    diagnostic = capability.diagnostic,
                )
            } else if (!capability.supported) {
                KeyMintCheckResult(ok = false, detail = capability.detail, diagnostic = capability.diagnostic)
            } else {
                rawRsaOaepMgf1Rejected(rawKey)
            }
        }
    }

    private fun generateRawRsaOaepKey(alias: String, useStrongBox: Boolean): RawRsaOaepKey {
        // Raw generation is deliberate. For KeyMint 1/2, VTS allows RSA_OAEP_MGF_DIGEST to be absent
        // from key characteristics, so generating via AndroidKeyStore and only reading characteristics
        // would falsely classify a conformant implementation as unsupported.
        // 这里必须走私有 keystore2 generateKey，而不是只看 AndroidKeyStore characteristics：
        // 对 KeyMint 1/2 来说，VTS 明确允许 characteristics 里没有 RSA_OAEP_MGF_DIGEST，
        // 否则会把“规范允许的缺失”误判成“不支持 MGF1”。
        //
        // AOSP references:
        // security/keymint/aidl/vts/functional/KeyMintTest.cpp (RsaOaepMGFDigestDefaultSuccess / Fail)
        // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/keymint/aidl/vts/functional/KeyMintTest.cpp
        // system/hardware/interfaces/keystore2/aidl/android/system/keystore2/IKeystoreSecurityLevel.aidl
        // https://android.googlesource.com/platform/system/hardware/interfaces/+/refs/heads/main/keystore2/aidl/android/system/keystore2/IKeystoreSecurityLevel.aidl
        val service = binderClient.getKeystoreService()
            ?: throw IllegalStateException("keystore2 service unavailable for native KeyMint probe.")
        val expectedSecurityLevel = if (useStrongBox) {
            Keystore2PrivateBinderClient.SECURITY_LEVEL_STRONGBOX
        } else {
            Keystore2PrivateBinderClient.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
        }
        val securityLevel = binderClient.resolveSecurityLevel(service, expectedSecurityLevel)
            ?: throw IllegalStateException("Selected native KeyMint security level unavailable.")
        val requestedDescriptor = binderClient.createKeyDescriptor(alias)
        return try {
            val generated = binderClient.generateRsaOaepKey(
                securityLevel = securityLevel,
                keyDescriptor = requestedDescriptor,
                mgfDigest = KEYMINT_DIGEST_SHA_256,
            ) ?: throw IllegalStateException("Raw keystore2 RSA-OAEP generation returned no metadata.")
            val metadata = binderClient.getMetadata(generated) ?: generated
            val returnedSecurityLevel = binderClient.getKeyMetadataSecurityLevel(metadata)
                ?: throw IllegalStateException("Raw keystore2 RSA-OAEP metadata omitted keySecurityLevel.")
            val certificate = binderClient.getCertificateBlob(generated)
                ?: throw IllegalStateException("Raw keystore2 RSA-OAEP generation returned no certificate.")
            val publicKey = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(certificate))
                .publicKey
            val authorizations = binderClient.getMetadataAuthorizations(metadata).mapNotNull { authorization ->
                authorization?.let {
                    val tag = binderClient.getAuthorizationTag(it) ?: return@let null
                    AuthorizationSummary(
                        tag = tag,
                        intValue = if (tag == KEYMINT_TAG_RSA_OAEP_MGF_DIGEST) {
                            binderClient.getAuthorizationDigestValue(it)
                        } else {
                            binderClient.getAuthorizationIntValue(it)
                        },
                        securityLevel = binderClient.getAuthorizationSecurityLevel(it),
                    )
                }
            }
            RawRsaOaepKey(
                service = service,
                cleanupDescriptor = requestedDescriptor,
                operationDescriptor = binderClient.resolveFollowUpDescriptor(requestedDescriptor, generated),
                securityLevel = securityLevel,
                expectedSecurityLevel = expectedSecurityLevel,
                returnedSecurityLevel = returnedSecurityLevel,
                publicKey = publicKey,
                authorizations = authorizations,
            )
        } catch (throwable: Throwable) {
            val cleanupFailure = binderClient.deleteKeyChecked(service, requestedDescriptor)
            if (cleanupFailure != null) {
                throw IllegalStateException(
                    "${binderClient.describeThrowable(throwable)}; partial-key cleanup failed: " +
                        binderClient.describeThrowable(cleanupFailure),
                )
            }
            throw throwable
        }
    }

    private fun withRawRsaOaepKey(
        alias: String,
        useStrongBox: Boolean,
        generationName: String,
        probeName: String,
        block: (RawRsaOaepKey) -> KeyMintCheckResult,
    ): KeyMintCheckResult {
        val rawKey = try {
            generateRawRsaOaepKey(alias, useStrongBox)
        } catch (throwable: Throwable) {
            return classifyMgfProbeFailure(generationName, throwable)
        }
        val result = try {
            block(rawKey)
        } catch (throwable: Throwable) {
            classifyMgfProbeFailure(probeName, throwable)
        }
        val cleanupFailure = binderClient.deleteKeyChecked(rawKey.service, rawKey.cleanupDescriptor)
        return if (cleanupFailure == null) {
            result
        } else {
            KeyMintCheckResult(
                ok = false,
                detail = result.detail + "; key cleanup failed: " +
                    binderClient.describeThrowable(cleanupFailure),
                executed = result.executed,
                diagnostic = listOfNotNull(
                    result.diagnostic,
                    "cleanup=failed, error=${binderClient.describeThrowable(cleanupFailure)}",
                ).joinToString("; "),
            )
        }
    }

    private fun rawRsaOaepMgf1RoundTrip(
        rawKey: RawRsaOaepKey,
        encrypted: ByteArray,
        payload: ByteArray,
    ): KeyMintCheckResult {
        val parameters = binderClient.createRsaOaepDecryptOperationParameters(
            digest = KEYMINT_DIGEST_SHA_256,
            mgfDigest = KEYMINT_DIGEST_SHA_256,
        )
        val operation = try {
            binderClient.getOperationHandle(
                binderClient.createOperation(rawKey.securityLevel, rawKey.operationDescriptor, parameters),
            ) ?: return KeyMintCheckResult(
                false,
                "Raw keystore2 MGF1 createOperation returned no operation handle.",
                diagnostic = rawKey.operationDiagnostic("begin=no_handle, digest=4, mgfDigest=4"),
            )
        } catch (throwable: Throwable) {
            return KeyMintCheckResult(
                false,
                "Raw keystore2 MGF1 SHA-256 begin failed: ${binderClient.describeThrowable(throwable)}",
                diagnostic = rawKey.operationDiagnostic(
                    "begin=failed, digest=4, mgfDigest=4, error=${binderClient.describeThrowable(throwable)}",
                ),
            )
        }
        return try {
            val decrypted = binderClient.finishOperation(operation, encrypted)
            val roundTrip = decrypted?.contentEquals(payload) == true
            KeyMintCheckResult(
                roundTrip,
                "rawBegin=true, roundTrip=$roundTrip, decryptedBytes=${decrypted?.size ?: 0}.",
                diagnostic = rawKey.operationDiagnostic(
                    "begin=ok, finish=ok, digest=4, mgfDigest=4, ciphertextBytes=${encrypted.size}, " +
                        "plaintextBytes=${payload.size}, decryptedBytes=${decrypted?.size ?: 0}, roundTrip=$roundTrip",
                ),
            )
        } catch (throwable: Throwable) {
            KeyMintCheckResult(
                false,
                "Raw keystore2 MGF1 SHA-256 finish failed: ${binderClient.describeThrowable(throwable)}",
                diagnostic = rawKey.operationDiagnostic(
                    "begin=ok, finish=failed, digest=4, mgfDigest=4, ciphertextBytes=${encrypted.size}, " +
                        "plaintextBytes=${payload.size}, error=${binderClient.describeThrowable(throwable)}",
                ),
            )
        } finally {
            runCatching { binderClient.abortOperation(operation) }
        }
    }

    private fun rawRsaOaepMgf1Rejected(rawKey: RawRsaOaepKey): KeyMintCheckResult {
        // We intentionally mirror the VTS matrix instead of inventing a broader rejection set.
        // The point of this probe is to detect backend divergence from AOSP semantics, so each case here
        // corresponds to a tested AOSP expectation: default SHA-1 rejection when absent from the key,
        // explicit SHA-224 incompatibility, and Digest.NONE unsupported.
        // 这里刻意只复刻 VTS 已定义的拒绝矩阵，而不是自创更多 case；检测目标是确认设备是否
        // 偏离 AOSP 语义，因此每个 case 都必须有上游规范依据。
        //
        // AOSP reference:
        // hardware/interfaces/security/keymint/aidl/vts/functional/KeyMintTest.cpp
        // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/keymint/aidl/vts/functional/KeyMintTest.cpp
        val results = keyMintMgfRejectionCases().map { rejectionCase ->
            rawRsaOaepMgf1BeginRejected(rawKey, rejectionCase)
        }
        val failures = results.filterNot { it.ok }
        return KeyMintCheckResult(
            ok = failures.isEmpty(),
            detail = results.joinToString("; ") { it.detail },
            diagnostic = results.mapNotNull { it.diagnostic }.joinToString(" | "),
        )
    }

    private fun rawRsaOaepMgf1BeginRejected(
        rawKey: RawRsaOaepKey,
        rejectionCase: MgfRejectionCase,
    ): KeyMintCheckResult {
        val parameters = binderClient.createRsaOaepDecryptOperationParameters(
            digest = KEYMINT_DIGEST_SHA_256,
            mgfDigest = rejectionCase.mgfDigest,
        )
        return try {
            val operation = binderClient.getOperationHandle(
                binderClient.createOperation(rawKey.securityLevel, rawKey.operationDescriptor, parameters),
            )
            runCatching { binderClient.abortOperation(operation) }
            KeyMintCheckResult(
                false,
                "${rejectionCase.name}=accepted",
                diagnostic = rawKey.operationDiagnostic(
                    "case=${rejectionCase.name}, begin=accepted, digest=4, " +
                        "mgfDigest=${rejectionCase.mgfDigest ?: "default"}",
                ),
            )
        } catch (throwable: Throwable) {
            if (!binderClient.isServiceSpecificException(throwable)) {
                return KeyMintCheckResult(
                    false,
                    "${rejectionCase.name}=failed(${binderClient.describeThrowable(throwable)})",
                    diagnostic = rawKey.operationDiagnostic(
                        "case=${rejectionCase.name}, begin=failed, digest=4, " +
                            "mgfDigest=${rejectionCase.mgfDigest ?: "default"}, " +
                            "error=${binderClient.describeThrowable(throwable)}",
                    ),
                )
            }
            val errorCode = binderClient.extractServiceSpecificErrorCode(throwable)
            val expected = errorCode in rejectionCase.expectedErrorCodes
            KeyMintCheckResult(
                expected,
                "${rejectionCase.name}=rejected(code=$errorCode, expected=$expected)",
                diagnostic = rawKey.operationDiagnostic(
                    "case=${rejectionCase.name}, begin=rejected, digest=4, " +
                        "mgfDigest=${rejectionCase.mgfDigest ?: "default"}, " +
                        "errorCode=$errorCode, expected=$expected",
                ),
            )
        }
    }

    private fun classifyMgfProbeFailure(name: String, throwable: Throwable): KeyMintCheckResult {
        val error = binderClient.describeThrowable(throwable)
        return KeyMintCheckResult(false, "$name failed: $error", diagnostic = "stage=$name, error=$error")
    }
}

private data class RawRsaOaepKey(
    val service: Any,
    val cleanupDescriptor: Any,
    val operationDescriptor: Any,
    val securityLevel: Any,
    val expectedSecurityLevel: Int,
    val returnedSecurityLevel: Int,
    val publicKey: PublicKey,
    val authorizations: List<AuthorizationSummary>,
)

private fun RawRsaOaepKey.operationDiagnostic(operation: String): String = buildString {
    append("serviceClass=")
    append(service.javaClass.name)
    append(", securityLevelClass=")
    append(securityLevel.javaClass.name)
    append(", descriptorClass=")
    append(operationDescriptor.javaClass.name)
    append(", publicKeyAlgorithm=")
    append(publicKey.algorithm)
    append(", ")
    append("selectedSecurityLevel=")
    append(expectedSecurityLevel)
    append(", returnedSecurityLevel=")
    append(returnedSecurityLevel)
    append(", authorizationCount=")
    append(authorizations.size)
    append(", mgfAuthorizations=")
    append(
        authorizations
            .filter { it.tag == KEYMINT_TAG_RSA_OAEP_MGF_DIGEST }
            .joinToString { authorization ->
                "value=${authorization.intValue ?: "null"}," +
                    "securityLevel=${authorization.securityLevel ?: "null"}"
            }
            .ifBlank { "none" },
    )
    append(", ")
    append(operation)
}
