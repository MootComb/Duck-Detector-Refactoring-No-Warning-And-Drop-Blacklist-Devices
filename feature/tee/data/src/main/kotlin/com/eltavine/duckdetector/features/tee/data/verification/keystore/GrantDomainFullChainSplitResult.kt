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

import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Locale

data class GrantDomainFullChainSplitResult(
    val executed: Boolean = false,
    val available: Boolean = false,
    val splitDetected: Boolean = false,
    val ownerChainLength: Int = 0,
    val granteeChainLength: Int = 0,
    val mismatchIndex: Int? = null,
    val granteeUid: Int? = null,
    val anomalyKind: GrantDomainAnomalyKind = GrantDomainAnomalyKind.UNAVAILABLE,
    val detail: String = "",
    val diagnosticCopyText: String = "",
)

enum class GrantDomainAnomalyKind {
    NONE,
    ISOLATED_CHAIN_SPLIT,
    ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN,
    ISOLATED_PRIVATE_READBACK_CRASH,
    UNAVAILABLE,
}

data class GrantDomainFullChainComparison(
    val splitDetected: Boolean,
    val mismatchIndex: Int? = null,
    val detail: String,
)

data class GrantDomainCertificateChain(
    val certificates: List<GrantDomainCertificateFingerprint> = emptyList(),
) {
    companion object {
        fun fromCertificates(certificates: List<X509Certificate>): GrantDomainCertificateChain {
            return GrantDomainCertificateChain(
                certificates = certificates.map { certificate ->
                    GrantDomainCertificateFingerprint.fromDer(certificate.encoded)
                },
            )
        }
    }
}

data class GrantDomainCertificateFingerprint(
    val derLength: Int,
    val sha256: String,
) {
    fun summary(): String {
        return "len=$derLength sha256=${sha256.take(16)}"
    }

    companion object {
        fun fromDer(der: ByteArray): GrantDomainCertificateFingerprint {
            val digest = MessageDigest.getInstance("SHA-256").digest(der)
            return GrantDomainCertificateFingerprint(
                derLength = der.size,
                sha256 = digest.joinToString(separator = "") { byte ->
                    "%02x".format(Locale.US, byte.toInt() and 0xff)
                },
            )
        }
    }
}
