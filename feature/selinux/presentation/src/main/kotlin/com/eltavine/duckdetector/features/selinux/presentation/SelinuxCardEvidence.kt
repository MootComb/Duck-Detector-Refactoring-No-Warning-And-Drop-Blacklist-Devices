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
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyRuleSet
private fun policyRuleDisplayName(result: SelinuxCheckResult): String {
    val rule = result.policyRule ?: return result.method
    return when (rule.set) {
        SelinuxPolicyRuleSet.DIRTY_SEPOLICY -> rule.edge
        SelinuxPolicyRuleSet.DROIDSPACES -> "Droidspaces: ${rule.edge}"
        SelinuxPolicyRuleSet.MSD -> "MSD: ${rule.edge}"
        SelinuxPolicyRuleSet.POLICY_OBSERVATION -> result.method
    }
}

internal fun trustedPolicyRuleVerdict(): String {
    return "Enforcing with dirty sepolicy rule"
}

internal fun trustedPolicyRuleSummary(result: SelinuxCheckResult): String {
    return "A trusted DirtySepolicy-style access query reported ${policyRuleDisplayName(result)} as allowed."
}

internal fun trustedPolicyRuleImpact(result: SelinuxCheckResult): String {
    return "A trusted DirtySepolicy-style access rule was allowed: ${policyRuleDisplayName(result)}."
}
