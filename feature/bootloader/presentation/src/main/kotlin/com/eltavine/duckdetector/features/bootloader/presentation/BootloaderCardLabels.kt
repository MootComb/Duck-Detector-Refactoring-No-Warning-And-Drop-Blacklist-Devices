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

package com.eltavine.duckdetector.features.bootloader.presentation

import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import com.eltavine.duckdetector.capability.attestation.domain.TeeTrustRoot
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderEvidenceMode
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingSeverity
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderReport
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderState
import com.eltavine.duckdetector.features.bootloader.presentation.model.BootloaderCardAssessment

internal fun proofLabel(mode: BootloaderEvidenceMode): String {
    return when (mode) {
        BootloaderEvidenceMode.ATTESTATION -> "Attest"
        BootloaderEvidenceMode.PROPERTIES_ONLY -> "Props"
        BootloaderEvidenceMode.UNAVAILABLE -> "N/A"
    }
}

internal fun stateLabel(state: BootloaderState): String {
    return when (state) {
        BootloaderState.VERIFIED -> "Verified"
        BootloaderState.SELF_SIGNED -> "Custom"
        BootloaderState.UNLOCKED -> "Unlocked"
        BootloaderState.FAILED_VERIFICATION -> "Failed"
        BootloaderState.LOCKED_UNKNOWN -> "Locked?"
        BootloaderState.UNKNOWN -> "Unknown"
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

internal fun trustLabel(trustRoot: TeeTrustRoot): String {
    return when (trustRoot) {
        TeeTrustRoot.GOOGLE -> "Google"
        TeeTrustRoot.GOOGLE_RKP -> "RKP"
        TeeTrustRoot.AOSP -> "AOSP"
        TeeTrustRoot.FACTORY -> "Factory"
        TeeTrustRoot.UNKNOWN -> "Unknown"
    }
}

internal fun trustStatus(report: BootloaderReport): DetectorStatus {
    return when {
        report.attestationChainLength == 0 -> DetectorStatus.danger()
        report.trustRoot == TeeTrustRoot.UNKNOWN -> DetectorStatus.danger()
        report.trustRoot == TeeTrustRoot.GOOGLE || report.trustRoot == TeeTrustRoot.GOOGLE_RKP ->
            DetectorStatus.allClear()

        report.trustRoot == TeeTrustRoot.AOSP -> DetectorStatus.warning()
        report.trustRoot == TeeTrustRoot.FACTORY -> DetectorStatus.info(InfoKind.SUPPORT)
        else -> DetectorStatus.info(InfoKind.SUPPORT)
    }
}

internal fun BootloaderReport.toCardAssessment(): BootloaderCardAssessment {
    val widevineFindings = findings.filter { finding ->
        finding.id.startsWith(WIDEVINE_FINDING_PREFIX)
    }
    return when {
        widevineFindings.any { it.severity == BootloaderFindingSeverity.DANGER } ->
            BootloaderCardAssessment.CONSISTENCY_CONFLICT

        widevineFindings.any { it.severity == BootloaderFindingSeverity.WARNING } ->
            BootloaderCardAssessment.CONSISTENCY_REVIEW

        else -> BootloaderCardAssessment.AUTHORITATIVE
    }
}

// Card severity may include Widevine; the State fact remains authoritative.
internal fun BootloaderReport.authoritativeStateStatus(): DetectorStatus {
    return when (state) {
        BootloaderState.VERIFIED -> DetectorStatus.allClear()
        BootloaderState.SELF_SIGNED,
        BootloaderState.LOCKED_UNKNOWN -> DetectorStatus.warning()

        BootloaderState.UNLOCKED,
        BootloaderState.FAILED_VERIFICATION -> DetectorStatus.danger()

        BootloaderState.UNKNOWN -> DetectorStatus.info(InfoKind.SUPPORT)
    }
}

internal const val WIDEVINE_FINDING_PREFIX = "widevine_"
