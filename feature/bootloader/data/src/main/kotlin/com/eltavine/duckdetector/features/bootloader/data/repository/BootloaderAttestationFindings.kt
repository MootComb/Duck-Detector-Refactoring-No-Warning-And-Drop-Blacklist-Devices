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

package com.eltavine.duckdetector.features.bootloader.data.repository

import com.eltavine.duckdetector.capability.attestation.data.AttestationSnapshot
import com.eltavine.duckdetector.capability.attestation.data.CertificateTrustResult
import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import com.eltavine.duckdetector.capability.attestation.domain.TeeTrustRoot
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFinding
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingGroup
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingSeverity

internal fun buildAttestationFindings(
    attestation: AttestationSnapshot,
    trust: CertificateTrustResult,
): List<BootloaderFinding> {
    if (!hasAttestation(attestation)) {
        val keyPairGenerationFailure =
            BootloaderSeverityRules.isKeyPairGenerationFailure(attestation.errorMessage)
        return listOf(
            BootloaderFinding(
                id = "attestation_unavailable",
                label = "Key attestation",
                value = if (keyPairGenerationFailure) "Failed" else "Unavailable",
                group = BootloaderFindingGroup.ATTESTATION,
                severity = if (keyPairGenerationFailure) {
                    BootloaderFindingSeverity.DANGER
                } else {
                    BootloaderFindingSeverity.INFO
                },
                detail = attestation.errorMessage
                    ?: "Key attestation did not expose a usable certificate chain.",
            ),
        )
    }

    val root = attestation.rootOfTrust
    return buildList {
        add(
            BootloaderFinding(
                id = "attestation_tier",
                label = "Attestation tier",
                value = tierLabel(attestation.tier),
                group = BootloaderFindingGroup.ATTESTATION,
                severity = when (attestation.tier) {
                    TeeTier.STRONGBOX,
                    TeeTier.TEE -> BootloaderFindingSeverity.SAFE

                    TeeTier.SOFTWARE -> BootloaderFindingSeverity.WARNING
                    TeeTier.NONE,
                    TeeTier.UNKNOWN -> BootloaderFindingSeverity.INFO
                },
                detail = buildString {
                    append("Certificate chain length: ${trust.chainLength}.")
                    if (attestation.challengeVerified) {
                        append(" Challenge matched generated nonce.")
                    }
                },
            ),
        )
        add(
            BootloaderFinding(
                id = "attestation_chain",
                label = "Certificate chain",
                value = if (trust.chainSignatureValid) "Valid" else "Broken",
                group = BootloaderFindingGroup.ATTESTATION,
                severity = when {
                    !trust.chainSignatureValid -> BootloaderFindingSeverity.DANGER
                    trust.expiredCertificates.isNotEmpty() || trust.issuerMismatches.isNotEmpty() ->
                        BootloaderFindingSeverity.DANGER

                    else -> BootloaderFindingSeverity.SAFE
                },
                detail = buildChainDetail(trust),
            ),
        )
        root?.verifiedBootState?.let { verifiedBootState ->
            add(
                BootloaderFinding(
                    id = "attested_boot_state",
                    label = "Attested boot state",
                    value = verifiedBootState,
                    group = BootloaderFindingGroup.ATTESTATION,
                    severity = stateSeverity(
                        resolveState(
                            attestation = attestation,
                            propertyContext = BootloaderPropertyContext.empty(),
                        ),
                    ),
                    detail = "RootOfTrust.verifiedBootState from attestation extension.",
                ),
            )
        }
        root?.deviceLocked?.let { locked ->
            add(
                BootloaderFinding(
                    id = "attested_lock",
                    label = "Attested deviceLocked",
                    value = locked.toString(),
                    group = BootloaderFindingGroup.ATTESTATION,
                    severity = if (locked) BootloaderFindingSeverity.SAFE else BootloaderFindingSeverity.DANGER,
                    detail = "RootOfTrust.deviceLocked from attestation extension.",
                ),
            )
        }
        root?.verifiedBootHashHex?.takeIf { it.isNotBlank() }?.let { hash ->
            add(
                BootloaderFinding(
                    id = "attested_boot_hash",
                    label = "Attested boot hash",
                    value = shortHex(hash),
                    group = BootloaderFindingGroup.ATTESTATION,
                    severity = if (isAllZeroHex(hash)) {
                        BootloaderFindingSeverity.DANGER
                    } else {
                        BootloaderFindingSeverity.INFO
                    },
                    detail = hash,
                    detailMonospace = true,
                ),
            )
        }
        root?.verifiedBootKeyHex?.takeIf { it.isNotBlank() }?.let { key ->
            add(
                BootloaderFinding(
                    id = "attested_boot_key",
                    label = "Attested boot key",
                    value = shortHex(key),
                    group = BootloaderFindingGroup.ATTESTATION,
                    severity = if (isAllZeroHex(key)) {
                        BootloaderFindingSeverity.DANGER
                    } else {
                        BootloaderFindingSeverity.INFO
                    },
                    detail = key,
                    detailMonospace = true,
                ),
            )
        }
    }
}

internal fun trustRootSeverity(trust: CertificateTrustResult): BootloaderFindingSeverity {
    return BootloaderSeverityRules.trustRootSeverity(trust)
}

internal fun trustRootDetail(trust: CertificateTrustResult): String {
    return buildString {
        append("Chain length: ${trust.chainLength}. ")
        append("Root classification: ${trustRootLabel(trust.trustRoot)}.")
        if (trust.rootFingerprint != null) {
            appendLine()
            append("Root fingerprint: ${trust.rootFingerprint}")
        }
        if (trust.issuerMismatches.isNotEmpty()) {
            appendLine()
            append(trust.issuerMismatches.joinToString(separator = "\n"))
        }
        if (trust.expiredCertificates.isNotEmpty()) {
            appendLine()
            append(trust.expiredCertificates.joinToString(separator = "\n"))
        }
    }
}

internal fun buildChainDetail(trust: CertificateTrustResult): String {
    return buildString {
        append("Chain signatures valid: ${trust.chainSignatureValid}.")
        if (trust.googleRootMatched) {
            append(" Google attestation root matched.")
        }
        if (trust.issuerMismatches.isNotEmpty()) {
            appendLine()
            append(trust.issuerMismatches.joinToString(separator = "\n"))
        }
        if (trust.expiredCertificates.isNotEmpty()) {
            appendLine()
            append(trust.expiredCertificates.joinToString(separator = "\n"))
        }
    }
}

internal fun trustRootLabel(trustRoot: TeeTrustRoot): String {
    return when (trustRoot) {
        TeeTrustRoot.GOOGLE -> "Google"
        TeeTrustRoot.GOOGLE_RKP -> "Google RKP"
        TeeTrustRoot.AOSP -> "AOSP"
        TeeTrustRoot.FACTORY -> "Factory"
        TeeTrustRoot.UNKNOWN -> "Unknown"
    }
}

internal fun tierLabel(tier: TeeTier): String {
    return when (tier) {
        TeeTier.STRONGBOX -> "StrongBox"
        TeeTier.TEE -> "TEE"
        TeeTier.SOFTWARE -> "Software"
        TeeTier.NONE -> "None"
        TeeTier.UNKNOWN -> "Unknown"
    }
}

private fun shortHex(value: String): String {
    val cleaned = value.filterNot { it.isWhitespace() || it == ':' }
    return if (cleaned.length > 16) cleaned.take(16) + "…" else cleaned
}

private fun isAllZeroHex(value: String?): Boolean {
    val cleaned = value
        ?.filterNot { it.isWhitespace() || it == ':' }
        ?.lowercase()
        .orEmpty()
    return cleaned.isNotBlank() && cleaned.all { it == '0' }
}

internal fun hasAttestation(snapshot: AttestationSnapshot): Boolean {
    return snapshot.rawCertificates.isNotEmpty() || snapshot.rootOfTrust != null
}
