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

import java.io.ByteArrayInputStream
import java.lang.reflect.InvocationTargetException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

interface Keystore2PrivateGrantFailureResult

data class Keystore2PrivateGrantConstants(
    val domainApp: Int,
    val domainGrant: Int,
    val permissionUse: Int,
    val permissionGetInfo: Int,
    val permissionUpdate: Int,
    val transactionGetKeyEntry: Int,
    val transactionGrant: Int,
    val transactionUngrant: Int,
) {
    val grantAccessVector: Int = permissionUse or permissionGetInfo
}

data class Keystore2PrivateGrantDescriptorSpec(
    val domain: Int,
    val nspace: Long,
    val alias: String?,
) {
    companion object {
        fun app(alias: String): Keystore2PrivateGrantDescriptorSpec {
            return Keystore2PrivateGrantDescriptorSpec(
                domain = Keystore2PrivateGrantClient.DOMAIN_APP_FALLBACK,
                nspace = -1L,
                alias = alias,
            )
        }

        fun grant(grantId: Long): Keystore2PrivateGrantDescriptorSpec {
            return Keystore2PrivateGrantDescriptorSpec(
                domain = Keystore2PrivateGrantClient.DOMAIN_GRANT_FALLBACK,
                nspace = grantId,
                alias = null,
            )
        }
    }
}

data class Keystore2PrivateGrantResult(
    val available: Boolean = false,
    val phase: Keystore2PrivateGrantPhase,
    val errorKind: Keystore2PrivateGrantErrorKind = Keystore2PrivateGrantErrorKind.NONE,
    val grantId: Long? = null,
    val detail: String = "",
    val throwable: Throwable? = null,
) : Keystore2PrivateGrantFailureResult {
    companion object {
        fun unavailable(
            phase: Keystore2PrivateGrantPhase,
            errorKind: Keystore2PrivateGrantErrorKind = Keystore2PrivateGrantErrorKind.SERVICE_UNAVAILABLE,
            detail: String,
            throwable: Throwable? = null,
        ): Keystore2PrivateGrantResult {
            return Keystore2PrivateGrantResult(
                available = false,
                phase = phase,
                errorKind = errorKind,
                detail = detail,
                throwable = throwable,
            )
        }
    }
}

data class Keystore2PrivateGrantChainResult(
    val available: Boolean = false,
    val phase: Keystore2PrivateGrantPhase,
    val errorKind: Keystore2PrivateGrantErrorKind = Keystore2PrivateGrantErrorKind.NONE,
    val chain: GrantDomainCertificateChain = GrantDomainCertificateChain(),
    val detail: String = "",
    val throwable: Throwable? = null,
) : Keystore2PrivateGrantFailureResult {
    companion object {
        fun unavailable(
            phase: Keystore2PrivateGrantPhase,
            errorKind: Keystore2PrivateGrantErrorKind = Keystore2PrivateGrantErrorKind.SERVICE_UNAVAILABLE,
            detail: String,
            throwable: Throwable? = null,
        ): Keystore2PrivateGrantChainResult {
            return Keystore2PrivateGrantChainResult(
                available = false,
                phase = phase,
                errorKind = errorKind,
                detail = detail,
                throwable = throwable,
            )
        }
    }
}

enum class Keystore2PrivateGrantPhase {
    PRIVATE_GRANT,
    PRIVATE_GET_KEY_ENTRY_APP,
    PRIVATE_GET_KEY_ENTRY_GRANT,
    PRIVATE_OWNER_REPLAY_GRANT,
    ISOLATED_BINDER_READBACK,
    PRIVATE_UNGRANT,
}

enum class Keystore2PrivateGrantErrorKind {
    NONE,
    KEY_NOT_FOUND,
    PERMISSION_DENIED,
    SERVICE_UNAVAILABLE,
    HIDDEN_API_FAILURE,
    PARCEL_OR_REFLECTION_FAILURE,
    UNGRANT_FAILED,
}

internal fun buildDefaultKeystore2PrivateGrantConstants(): Keystore2PrivateGrantConstants {
    return Keystore2PrivateGrantConstants(
        domainApp = Keystore2PrivateGrantClient.DOMAIN_APP_FALLBACK,
        domainGrant = Keystore2PrivateGrantClient.DOMAIN_GRANT_FALLBACK,
        permissionUse = Keystore2PrivateGrantClient.KEY_PERMISSION_USE_FALLBACK,
        permissionGetInfo = Keystore2PrivateGrantClient.KEY_PERMISSION_GET_INFO_FALLBACK,
        permissionUpdate = Keystore2PrivateGrantClient.KEY_PERMISSION_UPDATE_FALLBACK,
        transactionGetKeyEntry = Keystore2PrivateGrantClient.TRANSACTION_GET_KEY_ENTRY_FALLBACK,
        transactionGrant = Keystore2PrivateGrantClient.TRANSACTION_GRANT_FALLBACK,
        transactionUngrant = Keystore2PrivateGrantClient.TRANSACTION_UNGRANT_FALLBACK,
    )
}

internal fun classifyKeystore2PrivateGrantFailure(
    throwableClassName: String,
    message: String?,
    serviceSpecificErrorCode: Int?,
): Keystore2PrivateGrantErrorKind {
    if (serviceSpecificErrorCode == Keystore2PrivateGrantClient.RESPONSE_CODE_KEY_NOT_FOUND) {
        return Keystore2PrivateGrantErrorKind.KEY_NOT_FOUND
    }
    if (serviceSpecificErrorCode == Keystore2PrivateGrantClient.RESPONSE_CODE_PERMISSION_DENIED) {
        return Keystore2PrivateGrantErrorKind.PERMISSION_DENIED
    }
    val text = message.orEmpty()
    return when {
        text.contains("No key found by the given alias", ignoreCase = true) ||
            text.contains("KEY_NOT_FOUND", ignoreCase = true) -> Keystore2PrivateGrantErrorKind.KEY_NOT_FOUND
        text.contains("permission denied", ignoreCase = true) ||
            text.contains("PERMISSION_DENIED", ignoreCase = true) -> Keystore2PrivateGrantErrorKind.PERMISSION_DENIED
        throwableClassName.contains("ReflectiveOperationException") ||
            throwableClassName.contains("NoSuchMethod") ||
            throwableClassName.contains("NoSuchField") ||
            throwableClassName.contains("ClassNotFound") -> Keystore2PrivateGrantErrorKind.HIDDEN_API_FAILURE
        throwableClassName.contains("Parcel") ||
            throwableClassName.contains("InvocationTargetException") ||
            throwableClassName.contains("IllegalAccess") -> Keystore2PrivateGrantErrorKind.PARCEL_OR_REFLECTION_FAILURE
        else -> Keystore2PrivateGrantErrorKind.SERVICE_UNAVAILABLE
    }
}

internal fun chainFromCertificateBlobs(
    leaf: ByteArray?,
    remainingChain: ByteArray?,
): GrantDomainCertificateChain {
    val fingerprints = buildList {
        leaf?.takeIf { it.isNotEmpty() }?.let { add(GrantDomainCertificateFingerprint.fromDer(it)) }
        decodeX509Certificates(remainingChain).forEach { certificate ->
            add(GrantDomainCertificateFingerprint.fromDer(certificate.encoded))
        }
    }
    return GrantDomainCertificateChain(fingerprints)
}

private fun decodeX509Certificates(blob: ByteArray?): List<X509Certificate> {
    if (blob == null || blob.isEmpty()) {
        return emptyList()
    }
    return runCatching {
        val factory = CertificateFactory.getInstance("X.509")
        factory.generateCertificates(ByteArrayInputStream(blob))
            .filterIsInstance<X509Certificate>()
    }.getOrDefault(emptyList())
}
