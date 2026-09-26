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

import com.eltavine.duckdetector.features.tee.data.verification.keystore.SupplementaryAttestationInfoAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.UpdateSubcomponentStaleResponseAnomalyKind
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceItem
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel

internal fun MutableList<TeeEvidenceItem>.addKeystoreIndicators(artifacts: TeeScanArtifacts) {
    if (artifacts.keystore2Hook.javaHookDetected) {
        add(
            fact(
                "Keystore2",
                "Binder reply fingerprint matched a Java-hook style path.",
                TeeSignalLevel.FAIL
            )
        )
    }
    if (artifacts.legacyKeystorePath.executed &&
        artifacts.legacyKeystorePath.legacyMaterialAvailable &&
        !artifacts.legacyKeystorePath.chainMatches
    ) {
        add(
            fact(
                "Legacy keystore",
                "Legacy USRCERT_/CACERT_ path diverged from the Java KeyStore certificate chain.",
                TeeSignalLevel.WARN
            )
        )
    }
    if (artifacts.listEntriesConsistency.executed &&
        (artifacts.listEntriesConsistency.inconsistent || artifacts.listEntriesConsistency.badParcelableLikeCrash)
    ) {
        add(
            fact(
                "listEntries",
                "containsAlias()/aliases() diverged or crashed with a BadParcelable-style path.",
                TeeSignalLevel.FAIL
            )
        )
    }
    if (artifacts.listEntriesBatched.executed &&
        (artifacts.listEntriesBatched.cursorEchoed || artifacts.listEntriesBatched.expectedNextMissing)
    ) {
        add(
            fact(
                "listEntriesBatched",
                "Keystore2 listEntriesBatched(startPastAlias) diverged from expected cursor semantics.",
                if (artifacts.listEntriesBatched.cursorEchoed) TeeSignalLevel.FAIL else TeeSignalLevel.WARN
            )
        )
    }
    if (artifacts.keyMetadataSemantics.executed &&
        (!artifacts.keyMetadataSemantics.usesKeyIdDomain || !artifacts.keyMetadataSemantics.aliasCleared)
    ) {
        add(
            fact(
                "Key metadata",
                "Keystore2 metadata.key did not normalize to KEY_ID semantics.",
                TeeSignalLevel.FAIL
            )
        )
    }
    if (artifacts.keyMetadataShape.executed &&
        (!artifacts.keyMetadataShape.modificationTimeValid || !artifacts.keyMetadataShape.hasOriginTag)
    ) {
        add(
            fact(
                "Key metadata",
                "Keystore2 metadata omitted expected modification time or ORIGIN authorization tags.",
                TeeSignalLevel.FAIL
            )
        )
    }
    if (artifacts.keyboxImport.executed && !artifacts.keyboxImport.markerPreserved) {
        add(
            fact(
                "Keybox import",
                "Imported marker certificate came back rewritten.",
                TeeSignalLevel.FAIL
            )
        )
    }
    if (artifacts.importKeyRetainedAttestationNarrative.executed &&
        artifacts.importKeyRetainedAttestationNarrative.retainedNarrativeDetected
    ) {
        add(
            fact(
                "ImportKey narrative",
                "ImportKey retained attestation narrative detected.",
                TeeSignalLevel.FAIL,
            )
        )
    }
    when (artifacts.supplementaryAttestationInfo.anomalyKind) {
        SupplementaryAttestationInfoAnomalyKind.MISSING_ATTESTATION_MODULE_HASH -> {
            add(
                fact(
                    "Module hash",
                    "getSupplementaryAttestationInfo(MODULE_HASH) returned module info, but attestation omitted MODULE_HASH.",
                    TeeSignalLevel.WARN,
                    hiddenCopyText = artifacts.supplementaryAttestationInfo.diagnosticCopyText,
                )
            )
        }
        SupplementaryAttestationInfoAnomalyKind.MISMATCH -> {
            add(
                fact(
                    "Module hash",
                    "Attested MODULE_HASH did not match getSupplementaryAttestationInfo(MODULE_HASH).",
                    TeeSignalLevel.WARN,
                    hiddenCopyText = artifacts.supplementaryAttestationInfo.diagnosticCopyText,
                )
            )
        }
        SupplementaryAttestationInfoAnomalyKind.UNEXPECTED_ATTESTATION_MODULE_HASH -> {
            add(
                fact(
                    "Module hash",
                    "Attestation carried MODULE_HASH while getSupplementaryAttestationInfo(MODULE_HASH) was unavailable.",
                    TeeSignalLevel.WARN,
                    hiddenCopyText = artifacts.supplementaryAttestationInfo.diagnosticCopyText,
                )
            )
        }
        SupplementaryAttestationInfoAnomalyKind.NONE,
        SupplementaryAttestationInfoAnomalyKind.UNSUPPORTED -> Unit
    }
    if (
        artifacts.updateSubcomponentStaleResponsePersistence.anomalyKind ==
        UpdateSubcomponentStaleResponseAnomalyKind.STALE_TEE_RESPONSE_AFTER_KEY_ID_UPDATE
    ) {
        add(
            fact(
                "Update persistence",
                "UpdateSubcomponent stale TEE response persistence detected.",
                TeeSignalLevel.FAIL,
            )
        )
    }
}
