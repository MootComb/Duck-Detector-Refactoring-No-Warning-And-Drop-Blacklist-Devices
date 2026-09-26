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

internal fun buildKeyMintDiagnosticCopyText(
    sdkInt: Int,
    useStrongBox: Boolean,
    attestationVersion: Int?,
    keymasterVersion: Int?,
    declaredKeyMintVersion: Int?,
    legacyKeymasterDeclared: Boolean,
    securityLevelsConsistent: Boolean,
    runtimeIdentityConsistent: Boolean,
    checks: List<KeyMintDiagnosticEntry>,
): String = buildString {
    appendLine("keymint-capability-diagnostic=v1")
    appendLine("sdkInt=$sdkInt")
    appendLine("useStrongBox=$useStrongBox")
    appendLine("attestationVersion=${attestationVersion ?: "null"}")
    appendLine("keymasterVersion=${keymasterVersion ?: "null"}")
    appendLine("declaredKeyMintVersion=${declaredKeyMintVersion ?: "null"}")
    appendLine("legacyKeymasterDeclared=$legacyKeymasterDeclared")
    appendLine("securityLevelsConsistent=$securityLevelsConsistent")
    appendLine("runtimeIdentityConsistent=$runtimeIdentityConsistent")
    appendLine("checks:")
    checks.forEach { check ->
        appendLine("- ${check.name}: executed=${check.executed}, ok=${check.ok}, detail=${check.detail}")
        check.diagnostic?.takeIf { it.isNotBlank() }?.let { diagnostic ->
            appendLine("  diagnostic=$diagnostic")
        }
    }
}

internal data class KeyMintDiagnosticEntry(
    val name: String,
    val executed: Boolean,
    val ok: Boolean,
    val detail: String,
    val diagnostic: String?,
)
