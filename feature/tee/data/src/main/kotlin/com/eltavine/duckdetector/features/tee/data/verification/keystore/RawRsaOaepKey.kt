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

import java.security.PublicKey

internal data class RawRsaOaepKey(
    val service: Any,
    val cleanupDescriptor: Any,
    val operationDescriptor: Any,
    val securityLevel: Any,
    val expectedSecurityLevel: Int,
    val returnedSecurityLevel: Int,
    val publicKey: PublicKey,
    val authorizations: List<AuthorizationSummary>,
)

internal fun RawRsaOaepKey.operationDiagnostic(operation: String): String = buildString {
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
