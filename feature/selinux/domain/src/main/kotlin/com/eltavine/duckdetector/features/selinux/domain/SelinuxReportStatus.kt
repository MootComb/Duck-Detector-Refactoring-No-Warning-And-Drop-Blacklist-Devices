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

package com.eltavine.duckdetector.features.selinux.domain

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind

fun SelinuxReport.toDetectorStatus(): DetectorStatus {
    val contextValidity = contextValidityResult(this)
    val procAttrCurrent = procAttrCurrentResult(this)
    val policyloadSeqno = policyloadSeqnoResult(this)
    val dirtyPolicyHit = firstTrustedPolicyRuleHit(this)
    val appZygoteCarrierState = contextValiditySupportState(contextValidity)
    return when (stage) {
        SelinuxStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
        SelinuxStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
        SelinuxStage.READY -> when (mode) {
            SelinuxMode.ENFORCING -> when {
                auditIntegrity?.state == SelinuxAuditIntegrityState.TAMPERED -> DetectorStatus.danger()
                contextValidity?.status == SelinuxContextValidityLabels.BITPAIR_KSU_PRESENT -> DetectorStatus.danger()
                policyloadSeqno?.isSecure == false -> DetectorStatus.danger()
                procAttrCurrent?.isSecure == false -> DetectorStatus.danger()
                dirtyPolicyHit != null -> DetectorStatus.warning()
                appZygoteCarrierState == AppZygoteCarrierSupportState.UNTRUSTED -> DetectorStatus.warning()
                appZygoteCarrierState == AppZygoteCarrierSupportState.FAILED -> DetectorStatus.info(InfoKind.SUPPORT)
                contextValidity?.status == SelinuxContextValidityLabels.BITPAIR_SELF_TEST_FAILED -> DetectorStatus.warning()
                contextValidity?.status == SelinuxContextValidityLabels.BITPAIR_AMBIGUOUS -> DetectorStatus.warning()
                policyAnalysis?.weakness == SelinuxPolicyWeakness.SEVERE ||
                        policyAnalysis?.weakness == SelinuxPolicyWeakness.MODERATE ||
                        auditIntegrity?.state == SelinuxAuditIntegrityState.EXPOSED ||
                        auditIntegrity?.state == SelinuxAuditIntegrityState.RESIDUE -> DetectorStatus.warning()

                else -> DetectorStatus.allClear()
            }

            SelinuxMode.PERMISSIVE, SelinuxMode.DISABLED -> DetectorStatus.danger()
            SelinuxMode.UNKNOWN -> DetectorStatus.info(InfoKind.ERROR)
        }
    }
}

fun contextValidityResult(report: SelinuxReport): SelinuxCheckResult? {
    return report.methods.firstOrNull { it.method == SelinuxContextValidityLabels.METHOD_LABEL }
}

fun procAttrCurrentResult(report: SelinuxReport): SelinuxCheckResult? {
    return report.methods.firstOrNull { it.method == SelinuxProcAttrCurrentLabels.METHOD_LABEL }
}

fun policyloadSeqnoResult(report: SelinuxReport): SelinuxCheckResult? {
    return report.methods.firstOrNull { it.method == SelinuxPolicyloadSeqnoLabels.METHOD_LABEL }
}

fun firstTrustedPolicyRuleHit(report: SelinuxReport): SelinuxCheckResult? {
    return report.methods.firstOrNull {
        isPolicyRuleMethod(it.method) &&
            it.status == "Allowed" &&
            it.isSecure == false &&
            it.dirtyPolicyTrusted
    }
}

fun isPolicyRuleMethod(method: String): Boolean {
    return method.startsWith("Dirty sepolicy rule: ") ||
        method.startsWith("Droidspaces checker: ") ||
        method.startsWith("MSD checker: ")
}

fun contextValiditySupportState(result: SelinuxCheckResult?): AppZygoteCarrierSupportState {
    if (result?.method != SelinuxContextValidityLabels.METHOD_LABEL ||
        result.status != SelinuxContextValidityLabels.BITPAIR_UNSUPPORTED
    ) {
        return AppZygoteCarrierSupportState.AVAILABLE
    }
    return when {
        result.details.orEmpty().contains("Carrier state=untrusted") ->
            AppZygoteCarrierSupportState.UNTRUSTED
        result.details.orEmpty().contains("Carrier state=failed") ->
            AppZygoteCarrierSupportState.FAILED
        else -> AppZygoteCarrierSupportState.AVAILABLE
    }
}

enum class AppZygoteCarrierSupportState {
    AVAILABLE,
    FAILED,
    UNTRUSTED,
}
