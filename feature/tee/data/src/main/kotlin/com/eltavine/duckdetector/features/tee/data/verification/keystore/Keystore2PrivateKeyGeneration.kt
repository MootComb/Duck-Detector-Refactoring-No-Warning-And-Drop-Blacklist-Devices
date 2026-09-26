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

import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2PrivateBinderClient.Companion.DEFAULT_GENERATE_MODE_ALIAS_PREFIX

internal fun Keystore2PrivateBinderClient.generateAttestationKey(securityLevel: Any, keyDescriptor: Any): Any? {
    var lastFailure: Throwable? = null
    val parameterSets = listOf(
        listOf(
            createKeyParameter(0x10000002, 3),
            createKeyParameter(0x30000003, 256),
            createKeyParameter(0x1000000A, 1),
            createKeyParameter(0x20000001, 7),
            createKeyParameter(0x20000005, 4),
            createKeyParameter(0x700001F7, true),
        ),
        listOf(
            createKeyParameter(0x10000002, 3),
            createKeyParameter(0x30000003, 256),
            createKeyParameter(0x1000000A, 1),
            createKeyParameter(0x20000001, 7),
            createKeyParameter(0x20000005, 0),
            createKeyParameter(0x700001F7, true),
        ),
        listOf(
            createKeyParameter(0x10000002, 3),
            createKeyParameter(0x30000003, 256),
            createKeyParameter(0x1000000A, 1),
            createKeyParameter(0x20000001, 7),
            createKeyParameter(0x700001F7, true),
        ),
    )

    for (parameters in parameterSets) {
        try {
            return invokeGenerateKey(securityLevel, keyDescriptor, null, parameters)
        } catch (throwable: Throwable) {
            lastFailure = throwable
        }
    }

    throw lastFailure ?: IllegalStateException("Unable to provision PURPOSE_ATTEST_KEY test key.")
}

internal fun Keystore2PrivateBinderClient.generateSigningKey(
    securityLevel: Any,
    keyDescriptor: Any,
    attestationKeyDescriptor: Any?,
    attest: Boolean,
): Any? {
    val parameters = buildSigningKeyParameters(attest)
    return invokeGenerateKey(securityLevel, keyDescriptor, attestationKeyDescriptor, parameters)
}

internal fun Keystore2PrivateBinderClient.generateRsaOaepKey(
    securityLevel: Any,
    keyDescriptor: Any,
    mgfDigest: Int,
): Any? {
    val parameters = listOf(
        createKeyParameter(getTagValue("ALGORITHM") ?: 0x10000002, getAlgorithmValue("RSA") ?: 1),
        createKeyParameter(getTagValue("KEY_SIZE") ?: 0x30000003, 2048),
        createKeyParameter(getTagValue("PURPOSE") ?: 0x20000001, getKeyPurposeValue("DECRYPT") ?: 1),
        createKeyParameter(getTagValue("DIGEST") ?: 0x20000005, getDigestValue("SHA_2_256") ?: 4),
        createKeyParameter(getTagValue("PADDING") ?: 0x20000006, getPaddingModeValue("RSA_OAEP") ?: 2),
        createKeyParameter(getTagValue("RSA_PUBLIC_EXPONENT") ?: 0x500000C8, 65537L),
        createKeyParameter(getTagValue("RSA_OAEP_MGF_DIGEST") ?: 0x200000CB, mgfDigest),
        createKeyParameter(getTagValue("NO_AUTH_REQUIRED") ?: 0x700001F7, true),
    )
    return invokeGenerateKey(securityLevel, keyDescriptor, null, parameters)
}

internal fun Keystore2PrivateBinderClient.captureGenerateKeyReply(useStrongBox: Boolean = false): GenerateKeyReplyCaptureResult {
    val sessionResult = openSession(
        useStrongBox = useStrongBox,
        captureGenerateKeyReplies = true,
    )
    val session = sessionResult.session ?: return GenerateKeyReplyCaptureResult(
        available = false,
        detail = sessionResult.failureReason ?: "Keystore2 private binder proxy session unavailable.",
    )
    val alias = "${DEFAULT_GENERATE_MODE_ALIAS_PREFIX}_${System.nanoTime()}"
    val keyDescriptor = createKeyDescriptor(alias)

    return try {
        val capture = invokeGenerateKeyWithReplyCapture(
            securityLevel = session.securityLevel,
            keyDescriptor = keyDescriptor,
            attestationKeyDescriptor = null,
            parameters = buildGenerateModeSigningKeyParameters(),
        )
        when {
            capture.rawReply != null -> GenerateKeyReplyCaptureResult(
                available = true,
                rawRequest = capture.rawRequest,
                requestPrefix = capture.requestPrefix,
                rawReply = capture.rawReply,
                rawPrefix = capture.rawPrefix,
                detail = buildString {
                    append("Captured generateKey reply via private binder proxy transact")
                    append("; bytes=")
                    append(capture.rawReply.size)
                    capture.rawRequest?.let {
                        append(", requestBytes=")
                        append(it.size)
                    }
                    capture.transactionCode?.let {
                        append(", code=")
                        append(it)
                    }
                    capture.transactReturned?.let {
                        append(", transactReturned=")
                        append(it)
                    }
                    capture.throwable?.let {
                        append(", invocation=")
                        append(describeThrowable(it))
                    }
                },
            )
            else -> GenerateKeyReplyCaptureResult(
                available = false,
                rawRequest = capture.rawRequest,
                requestPrefix = capture.requestPrefix,
                detail = capture.failureReason
                    ?: capture.throwable?.let(::describeThrowable)
                    ?: "generateKey reply capture did not observe a marshalled reply.",
            )
        }
    } catch (throwable: Throwable) {
        GenerateKeyReplyCaptureResult(
            available = false,
            detail = describeThrowable(throwable),
        )
    } finally {
        deleteKey(session.service, keyDescriptor)
        closeSession(session)
    }
}
