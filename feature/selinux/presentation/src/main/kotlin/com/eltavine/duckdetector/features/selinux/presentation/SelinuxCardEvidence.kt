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

package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxContextValidityLabels
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyloadSeqnoLabels
import com.eltavine.duckdetector.features.selinux.domain.SelinuxProcAttrCurrentLabels
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport

internal fun contextValidityResult(report: SelinuxReport): SelinuxCheckResult? {
    return report.methods.firstOrNull { it.method == SelinuxContextValidityLabels.METHOD_LABEL }
}

internal fun procAttrCurrentResult(report: SelinuxReport): SelinuxCheckResult? {
    return report.methods.firstOrNull { it.method == SelinuxProcAttrCurrentLabels.METHOD_LABEL }
}

internal fun policyloadSeqnoResult(report: SelinuxReport): SelinuxCheckResult? {
    return report.methods.firstOrNull { it.method == SelinuxPolicyloadSeqnoLabels.METHOD_LABEL }
}

internal fun firstTrustedPolicyRuleHit(report: SelinuxReport): SelinuxCheckResult? {
    return report.methods.firstOrNull {
        isPolicyRuleMethod(it.method) &&
            it.status == "Allowed" &&
            it.isSecure == false &&
            it.dirtyPolicyTrusted
    }
}

private fun isPolicyRuleMethod(method: String): Boolean {
    return method.startsWith("Dirty sepolicy rule: ") ||
        method.startsWith("Droidspaces checker: ") ||
        method.startsWith("MSD checker: ")
}

internal fun isMsdPolicyRuleMethod(method: String): Boolean {
    return method.startsWith("MSD checker: ")
}

internal fun isDroidspacesPolicyRuleMethod(method: String): Boolean {
    return method.startsWith("Droidspaces checker: ")
}

private fun policyRuleDisplayName(method: String): String {
    return when {
        method.startsWith("Dirty sepolicy rule: ") -> method.removePrefix("Dirty sepolicy rule: ")
        method.startsWith("Droidspaces checker: ") -> "Droidspaces: ${method.removePrefix("Droidspaces checker: ")}"
        method.startsWith("MSD checker: ") -> "MSD: ${method.removePrefix("MSD checker: ")}"
        else -> method
    }
}

internal fun msdPolicyRuleName(method: String): String {
    return method.removePrefix("MSD checker: ")
}

internal fun droidspacesPolicyRuleName(method: String): String {
    return method.removePrefix("Droidspaces checker: ")
}

internal fun trustedPolicyRuleVerdict(): String {
    return "Enforcing with dirty sepolicy rule"
}

internal fun trustedPolicyRuleSummary(result: SelinuxCheckResult): String {
    return "A trusted DirtySepolicy-style access query reported ${policyRuleDisplayName(result.method)} as allowed."
}

internal fun trustedPolicyRuleImpact(result: SelinuxCheckResult): String {
    return "A trusted DirtySepolicy-style access rule was allowed: ${policyRuleDisplayName(result.method)}."
}

internal fun contextValiditySupportState(result: SelinuxCheckResult?): AppZygoteCarrierSupportState {
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

internal enum class AppZygoteCarrierSupportState {
    AVAILABLE,
    FAILED,
    UNTRUSTED,
}
