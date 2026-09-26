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

package com.eltavine.duckdetector.features.tee.data.report

import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import com.eltavine.duckdetector.capability.attestation.domain.TeeTrustRoot
import com.eltavine.duckdetector.features.tee.data.verification.crl.RevokedCertificateEvidenceKind
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceItem
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import java.time.LocalDate
import java.time.Period
import kotlin.math.absoluteValue

internal fun shortFingerprint(input: String?): String {
    if (input.isNullOrBlank()) {
        return "Unavailable"
    }
    return "${input.take(12)}..."
}

internal fun indicatorValue(
    policyHardIndicators: List<TeeEvidenceItem>,
    policySoftIndicators: List<TeeEvidenceItem>,
    supplementaryIndicators: List<TeeEvidenceItem>,
): String {
    return "${policyHardIndicators.size} policy hard • " +
            "${policySoftIndicators.size} policy review • " +
            "${supplementaryIndicators.size} local"
}

internal fun List<TeeEvidenceItem>.highestPriority(): TeeEvidenceItem? {
    // Summary copy follows the same severity contract so WARN prose cannot hide red-card evidence.
    // 摘要文案遵循同一严重级别契约，避免 WARN 文案遮住红卡级证据。
    return firstOrNull { it.level == TeeSignalLevel.FAIL }
        ?: firstOrNull { it.level == TeeSignalLevel.WARN }
        ?: firstOrNull()
}

internal fun trustRootLabel(trustRoot: TeeTrustRoot): String = when (trustRoot) {
    TeeTrustRoot.GOOGLE_RKP -> "Google root"
    TeeTrustRoot.GOOGLE -> "Google root"
    TeeTrustRoot.AOSP -> "AOSP root"
    TeeTrustRoot.FACTORY -> "Factory root"
    TeeTrustRoot.UNKNOWN -> "Unknown"
}

internal fun normalizeTrustRoot(trustRoot: TeeTrustRoot): TeeTrustRoot = when (trustRoot) {
    TeeTrustRoot.GOOGLE_RKP -> TeeTrustRoot.GOOGLE
    else -> trustRoot
}

internal fun hasHardRevocation(artifacts: TeeScanArtifacts): Boolean {
    return artifacts.crl.revokedCertificates.any {
        it.evidenceKind == RevokedCertificateEvidenceKind.STANDARD_REVOCATION
    }
}

internal fun hasLocalMassAbuseRevocation(artifacts: TeeScanArtifacts): Boolean {
    // 临时本地口径：仅 checked-in 硬编码序列号命中时降级为 WARN，远端/联网 CRL 仍按标准吊销处理。
    return artifacts.crl.revokedCertificates.any {
        it.evidenceKind == RevokedCertificateEvidenceKind.LOCAL_MASS_ABUSE
    }
}

internal fun hasLocalTrustReviewSignals(artifacts: TeeScanArtifacts): Boolean {
    return artifacts.trust.expiredCertificates.isNotEmpty() || artifacts.trust.issuerMismatches.isNotEmpty()
}

internal fun TeeTier.displayName(): String = when (this) {
    TeeTier.UNKNOWN -> "Unknown"
    TeeTier.NONE -> "None"
    TeeTier.SOFTWARE -> "Software"
    TeeTier.TEE -> "TEE"
    TeeTier.STRONGBOX -> "StrongBox"
}

internal fun monthDistance(runtimePatch: String, attestedPatch: String): Int? {
    return runCatching {
        val runtime = parsePatchDate(runtimePatch)
        val attested = parsePatchDate(attestedPatch)
        if (runtime == null || attested == null) {
            null
        } else {
            val period = Period.between(runtime, attested)
            (period.years * 12 + period.months).absoluteValue
        }
    }.getOrNull()
}

private fun parsePatchDate(input: String): LocalDate? {
    val trimmed = input.trim()
    return when (trimmed.count { it == '-' }) {
        1 -> LocalDate.parse("$trimmed-01")
        2 -> LocalDate.parse(trimmed)
        else -> null
    }
}
