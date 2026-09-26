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

import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2PrivateGrantErrorKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackAnomalyKind
import com.eltavine.duckdetector.features.tee.domain.TeeGrantEvidence
import com.eltavine.duckdetector.features.tee.domain.TeeGrantProbe

// Each flag says whether the item's text, its sentence and its value from TeeReportGrantValues, names a
// key visibility divergence or a KEY_NOT_FOUND result. A probe's detail carries keystore2's own error
// text, which can name a missing key that no anomaly kind records.

internal fun isolatedDomainGrantEvidence(
    artifacts: TeeScanArtifacts,
    sentenceNamesKeyVisibility: Boolean = false,
): TeeGrantEvidence {
    val result = artifacts.grantDomainFullChainSplit
    return TeeGrantEvidence(
        probe = TeeGrantProbe.ISOLATED_DOMAIN,
        namesKeyVisibility = sentenceNamesKeyVisibility || result.detail.namesKeyVisibility(),
        namesMissingKey = result.anomalyKind == GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN ||
            result.detail.namesMissingKey(),
    )
}

internal fun selfDomainGrantEvidence(
    artifacts: TeeScanArtifacts,
    sentenceNamesKeyVisibility: Boolean = false,
): TeeGrantEvidence {
    val result = artifacts.grantSelfDomainFullChainSplit
    return TeeGrantEvidence(
        probe = TeeGrantProbe.SELF_DOMAIN,
        namesKeyVisibility = sentenceNamesKeyVisibility || result.detail.namesKeyVisibility(),
        namesMissingKey = result.anomalyKind == GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN ||
            result.anomalyKind == GrantSelfDomainAnomalyKind.SELF_GRANT_ATTESTATION_APP_KEY_NOT_FOUND ||
            result.detail.namesMissingKey(),
    )
}

internal fun callerBindingGrantEvidence(artifacts: TeeScanArtifacts): TeeGrantEvidence {
    val result = artifacts.syntheticGrantGranteeBlindReadback
    val cleanOwnerReplay = result.executed && result.available &&
        result.anomalyKind == SyntheticGrantGranteeBlindReadbackAnomalyKind.NONE
    val unavailableOwnerReplay = result.anomalyKind != SyntheticGrantGranteeBlindReadbackAnomalyKind.NON_GRANTEE_READBACK_ALLOWED &&
        result.anomalyKind != SyntheticGrantGranteeBlindReadbackAnomalyKind.SKIPPED_AFTER_EXISTING_GRANT_DANGER &&
        !cleanOwnerReplay
    return TeeGrantEvidence(
        probe = TeeGrantProbe.CALLER_BINDING,
        namesKeyVisibility = result.detail.namesKeyVisibility(),
        namesMissingKey = cleanOwnerReplay ||
            unavailableOwnerReplay && result.ownerReplayErrorKind == Keystore2PrivateGrantErrorKind.KEY_NOT_FOUND ||
            result.detail.namesMissingKey(),
    )
}

private fun String.namesKeyVisibility(): Boolean = contains("key visibility", ignoreCase = true)

private fun String.namesMissingKey(): Boolean = contains("KEY_NOT_FOUND", ignoreCase = true)
