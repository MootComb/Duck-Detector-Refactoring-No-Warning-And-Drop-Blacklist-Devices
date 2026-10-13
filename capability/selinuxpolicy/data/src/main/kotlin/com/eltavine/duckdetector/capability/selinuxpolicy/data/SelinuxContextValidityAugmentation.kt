/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

/**
 * Snapshot augmentation shared by the app zygote preload path and its tests: merges the native and
 * Java carrier self-check results, then layers the proc attr current, AVC lookup, policyload seqno
 * and Java dirty-policy probes onto the base snapshot.
 */
internal object SelinuxContextValidityAugmentation {

    private const val POLICYLOAD_SEQNO_PRELOAD_NOTE =
        "zygotePreloadName is required: the policyload/access seqno oracle must run before the isolated child loses app_zygote SELinuxfs access."

    internal fun mergeCarrierSelfCheckSnapshot(
        nativeSnapshot: SelinuxContextValiditySnapshot,
        javaCarrierSnapshot: SelinuxContextValiditySnapshot,
    ): SelinuxContextValiditySnapshot {
        return nativeSnapshot.copy(
            available = nativeSnapshot.available || javaCarrierSnapshot.available,
            probeAttempted = nativeSnapshot.probeAttempted || javaCarrierSnapshot.available,
            carrierContext = javaCarrierSnapshot.carrierContext ?: nativeSnapshot.carrierContext,
            carrierMatchesExpected = if (javaCarrierSnapshot.carrierContext != null) {
                javaCarrierSnapshot.carrierMatchesExpected
            } else {
                nativeSnapshot.carrierMatchesExpected
            },
            selinuxEnabled = javaCarrierSnapshot.selinuxEnabled ?: nativeSnapshot.selinuxEnabled,
            selinuxEnforced = javaCarrierSnapshot.selinuxEnforced ?: nativeSnapshot.selinuxEnforced,
            pidContextMatchesCurrent = javaCarrierSnapshot.pidContextMatchesCurrent
                ?: nativeSnapshot.pidContextMatchesCurrent,
            procSelfContextMatchesCurrent = javaCarrierSnapshot.procSelfContextMatchesCurrent
                ?: nativeSnapshot.procSelfContextMatchesCurrent,
            dyntransitionCheckPassed = javaCarrierSnapshot.dyntransitionCheckPassed
                ?: nativeSnapshot.dyntransitionCheckPassed,
            failureReason = nativeSnapshot.failureReason ?: javaCarrierSnapshot.failureReason,
        )
    }

    internal fun augmentPreloadSnapshot(
        baseSnapshot: SelinuxContextValiditySnapshot,
        currentUid: Int,
        appUid: Int,
        isUserBuild: Boolean,
        accessCheckBlockReason: String?,
        inspectProcAttrCurrent: () -> List<SelinuxProcAttrCurrentResult>,
        inspectAvcLookup: () -> SelinuxAvcLookupSnapshot = { SelinuxAvcLookupSnapshot() },
        inspectPolicyloadSeqno: () -> SelinuxPolicyloadSeqnoResult,
        checkAccess: (String, String, String, String) -> Boolean?,
    ): SelinuxContextValiditySnapshot {
        val carrierGateFailureReason = SelinuxContextValidityCarrierService.procAttrCurrentGateFailureReason(
            snapshot = baseSnapshot,
            appUid = appUid,
            uid = currentUid,
        )
        val snapshotWithProcAttr = if (carrierGateFailureReason == null) {
            baseSnapshot.copy(
                procAttrCurrentProbeAttempted = true,
                procAttrCurrentResults = inspectProcAttrCurrent(),
                procAttrCurrentFailureReason = null,
            )
        } else {
            baseSnapshot.copy(
                procAttrCurrentProbeAttempted = false,
                procAttrCurrentResults = emptyList(),
                procAttrCurrentFailureReason = carrierGateFailureReason,
            )
        }

        val snapshotWithAvc = snapshotWithProcAttr.copy(
            avcLookup = carrierGateFailureReason?.let {
                SelinuxAvcLookupSnapshot(state = SelinuxAvcLookupState.UNSUPPORTED, failureReason = it)
            } ?: inspectAvcLookup(),
        )
        val snapshotWithPolicyloadSeqno = snapshotWithAvc.applyPolicyloadSeqnoResult(
            failureReason = carrierGateFailureReason,
            inspectPolicyloadSeqno = inspectPolicyloadSeqno,
        )

        // The first android.os.SELinux.checkSELinuxAccess makes libselinux map and read the status page.
        accessCheckBlockReason?.let { reason ->
            return snapshotWithPolicyloadSeqno.copy(
                javaDirtyPolicyAvailable = false,
                javaDirtyPolicyProbeAttempted = false,
                javaDirtyPolicyCarrierContext = snapshotWithPolicyloadSeqno.carrierContext,
                javaDirtyPolicyCarrierMatchesExpected = snapshotWithPolicyloadSeqno.carrierMatchesExpected,
                javaDirtyPolicyQueryMethod = DIRTY_POLICY_QUERY_METHOD,
                javaDirtyPolicyFailureReason = reason,
            )
        }
        return snapshotWithPolicyloadSeqno.applyJavaDirtyPolicyResults(
            isUserBuild = isUserBuild,
            checkAccess = checkAccess,
        )
    }

    private fun SelinuxContextValiditySnapshot.applyPolicyloadSeqnoResult(
        failureReason: String?,
        inspectPolicyloadSeqno: () -> SelinuxPolicyloadSeqnoResult,
    ): SelinuxContextValiditySnapshot {
        if (failureReason != null) {
            return copy(
                policyloadSeqnoAvailable = false,
                policyloadSeqnoProbeAttempted = false,
                policyloadSeqnoState = SelinuxPolicyloadSeqnoState.UNAVAILABLE.name,
                policyloadSeqnoCarrierContext = carrierContext,
                policyloadSeqnoFailureReason = failureReason,
                policyloadSeqnoNotes = listOf(POLICYLOAD_SEQNO_PRELOAD_NOTE),
            )
        }
        val result = inspectPolicyloadSeqno()
        return copy(
            policyloadSeqnoAvailable = result.available,
            policyloadSeqnoProbeAttempted = result.probeAttempted,
            policyloadSeqnoState = result.state.name,
            policyloadSeqnoCarrierContext = carrierContext,
            policyloadSeqnoStatusSequence = result.statusSequence,
            policyloadSeqnoStatusPolicyload = result.statusPolicyload,
            policyloadSeqnoAccessSeqno = result.accessSeqno,
            policyloadSeqnoProcessClass = result.processClass,
            policyloadSeqnoFailureReason = result.failureReason,
            policyloadSeqnoNotes = result.notes.ifEmpty { listOf(POLICYLOAD_SEQNO_PRELOAD_NOTE) },
        )
    }
}
