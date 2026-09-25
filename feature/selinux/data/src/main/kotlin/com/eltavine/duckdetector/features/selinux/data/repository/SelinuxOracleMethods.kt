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

package com.eltavine.duckdetector.features.selinux.data.repository

import com.eltavine.duckdetector.capability.selinuxpolicy.data.DedicatedCarrierState
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxPolicyloadSeqnoState
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxProcAttrCurrentResult
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxContextValidityProbeResult
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxContextValidityState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxContextValidityLabels
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyloadSeqnoLabels
import com.eltavine.duckdetector.features.selinux.domain.SelinuxProcAttrCurrentLabels
import java.io.File

internal fun buildContextValidityMethod(
    result: SelinuxContextValidityProbeResult,
): SelinuxCheckResult {
    val status = when (result.state) {
        SelinuxContextValidityState.UNAVAILABLE ->
            SelinuxContextValidityLabels.BITPAIR_UNSUPPORTED

        SelinuxContextValidityState.CLEAN -> ""
        SelinuxContextValidityState.KSU_PRESENT ->
            SelinuxContextValidityLabels.BITPAIR_KSU_PRESENT

        SelinuxContextValidityState.AMBIGUOUS ->
            SelinuxContextValidityLabels.BITPAIR_AMBIGUOUS

        SelinuxContextValidityState.INCONSISTENT ->
            SelinuxContextValidityLabels.BITPAIR_SELF_TEST_FAILED
    }

    val detail = buildList {
        add("Carrier=${result.carrierContext ?: "<unreadable>"}\n")
        add("Carrier state=${result.carrierState.label}\n")
        add("Carrier match=${if (result.carrierMatchesExpected) "yes" else "no"}\n")
        add("Carrier control=${when (result.carrierControlValid) {
            true -> "accepted"
            false -> "rejected"
            null -> "unavailable"
        }}\n")
        add("Negative control=${when (result.negativeControlRejected) {
            true -> "rejected"
            false -> "accepted"
            null -> "unavailable"
        }}\n")
        add("File control=${when (result.fileControlValid) {
            true -> "accepted"
            false -> "rejected"
            null -> "unavailable"
        }}\n")
        add("File negative control=${when (result.fileNegativeControlRejected) {
            true -> "rejected"
            false -> "accepted"
            null -> "unavailable"
        }}\n")
        add("Oracle trusted=${if (result.oracleControlsPassed) "yes" else "no"}\n")
        add("Repeatability=${if (result.ksuResultsStable) "stable" else "unstable"}\n")
        add("Evidence source=${EvidenceSource.DEDICATED_CARRIER.label}\n")
        add(
            "Query=${
                when (result.state) {
                    SelinuxContextValidityState.UNAVAILABLE -> "Unavailable"
                    else -> result.queryMethod.ifBlank { "raw selinuxfs write" }
                }
            }\n"
        )
        when (result.state) {
            SelinuxContextValidityState.UNAVAILABLE ->
                add(
                    when (result.carrierState) {
                        DedicatedCarrierState.FAILED ->
                            "The dedicated app_zygote carrier failed before the oracle could produce a trusted result.\n"
                        DedicatedCarrierState.UNTRUSTED ->
                            "The dedicated app_zygote carrier was reachable but did not land in the expected app_zygote context.\n"
                        DedicatedCarrierState.OK ->
                            "The app_zygote carrier snapshot stayed unavailable.\n"
                    },
                )

            SelinuxContextValidityState.CLEAN ->
                add("KSU-specific contexts were not found by live policy.\n")

            SelinuxContextValidityState.KSU_PRESENT ->
                add("Both KSU-specific contexts were found by live policy.\n")

            SelinuxContextValidityState.AMBIGUOUS ->
                add("The two KSU-specific contexts split across live policy checks.\n")

            SelinuxContextValidityState.INCONSISTENT ->
                add("Context validity oracle self-test or repeatability failed, so the KSU verdict was not trusted.\n")
        }
        result.notes.forEach { note ->
            add(note)
        }
    }.joinToString(" | ")

    return SelinuxCheckResult(
        method = SelinuxContextValidityLabels.METHOD_LABEL,
        status = status,
        isSecure = when (result.state) {
            SelinuxContextValidityState.UNAVAILABLE -> null
            SelinuxContextValidityState.CLEAN -> true
            SelinuxContextValidityState.KSU_PRESENT -> false
            SelinuxContextValidityState.AMBIGUOUS -> null
            SelinuxContextValidityState.INCONSISTENT -> null
        },
        permissionDenied = false,
        details = detail,
    )
}

internal fun buildPolicyloadSeqnoMethod(
    result: SelinuxContextValidityProbeResult,
): SelinuxCheckResult {
    val state = runCatching {
        SelinuxPolicyloadSeqnoState.valueOf(result.policyloadSeqnoState.orEmpty())
    }.getOrDefault(SelinuxPolicyloadSeqnoState.UNAVAILABLE)
    val status = when (state) {
        SelinuxPolicyloadSeqnoState.CLEAN -> SelinuxPolicyloadSeqnoLabels.STATUS_CLEAN
        SelinuxPolicyloadSeqnoState.SUSPICIOUS -> SelinuxPolicyloadSeqnoLabels.STATUS_SUSPICIOUS
        SelinuxPolicyloadSeqnoState.INCONCLUSIVE -> SelinuxPolicyloadSeqnoLabels.STATUS_INCONCLUSIVE
        SelinuxPolicyloadSeqnoState.UNAVAILABLE -> SelinuxPolicyloadSeqnoLabels.STATUS_UNAVAILABLE
    }
    val detail = buildList {
        add("Evidence source=${EvidenceSource.DEDICATED_CARRIER.label}")
        add("Carrier=${result.policyloadSeqnoCarrierContext ?: result.carrierContext ?: "<unreadable>"}")
        add("zygotePreloadName required=yes")
        add("Probe attempted=${if (result.policyloadSeqnoProbeAttempted) "yes" else "no"}")
        result.policyloadSeqnoStatusSequence?.let { add("status.sequence=$it") }
        result.policyloadSeqnoStatusPolicyload?.let { add("status.policyload=$it") }
        result.policyloadSeqnoAccessSeqno?.let { add("access.avd.seqno=$it") }
        result.policyloadSeqnoProcessClass?.let { add("process class=$it") }
        (result.policyloadSeqnoFailureReason ?: result.failureReason)
            ?.let { add("Failure=$it") }
        result.policyloadSeqnoNotes.forEach(::add)
    }.joinToString(" | ")

    return SelinuxCheckResult(
        method = SelinuxPolicyloadSeqnoLabels.METHOD_LABEL,
        status = status,
        isSecure = when (state) {
            SelinuxPolicyloadSeqnoState.CLEAN -> true
            SelinuxPolicyloadSeqnoState.SUSPICIOUS -> false
            SelinuxPolicyloadSeqnoState.INCONCLUSIVE,
            SelinuxPolicyloadSeqnoState.UNAVAILABLE -> null
        },
        permissionDenied = false,
        details = detail,
    )
}

internal fun buildProcAttrCurrentMethod(
    result: SelinuxContextValidityProbeResult,
    source: EvidenceSource,
): SelinuxCheckResult {
    val outcomes = result.procAttrCurrentResults
    if (!result.procAttrCurrentProbeAttempted) {
        return SelinuxCheckResult(
            method = SelinuxProcAttrCurrentLabels.METHOD_LABEL,
            status = SelinuxProcAttrCurrentLabels.STATUS_UNSUPPORTED,
            isSecure = null,
            permissionDenied = false,
            details = listOfNotNull(
                "Evidence source=${source.label}",
                result.procAttrCurrentFailureReason ?: "Dedicated app_zygote attr/current write probe skipped.",
            ).joinToString(" | "),
        )
    }
    if (outcomes.isEmpty()) {
        return SelinuxCheckResult(
            method = SelinuxProcAttrCurrentLabels.METHOD_LABEL,
            status = SelinuxProcAttrCurrentLabels.STATUS_UNSUPPORTED,
            isSecure = null,
            permissionDenied = false,
            details = listOfNotNull(
                "Evidence source=${source.label}",
                result.procAttrCurrentFailureReason ?: "Dedicated app_zygote attr/current write probe returned no results.",
            ).joinToString(" | "),
        )
    }

    val detected = outcomes.filter(SelinuxProcAttrCurrentResult::detected)
    val clean = outcomes.all {
        it.outcomeClass == SelinuxProcAttrCurrentResult.OUTCOME_NORMAL_EINVAL
    }
    val status = when {
        detected.isNotEmpty() -> "Detected: ${detected.joinToString { it.label }}"
        clean -> SelinuxProcAttrCurrentLabels.STATUS_CLEAN
        else -> SelinuxProcAttrCurrentLabels.STATUS_UNSUPPORTED
    }
    val detail = listOf(
        "Evidence source=${source.label}",
        outcomes.joinToString(" | ") { outcome ->
            "${outcome.label}=${outcome.outcomeClass} target=${outcome.targetContext} raw=${outcome.rawMessage}"
        },
    ).joinToString(" | ")

    return SelinuxCheckResult(
        method = SelinuxProcAttrCurrentLabels.METHOD_LABEL,
        status = status,
        isSecure = when {
            detected.isNotEmpty() -> false
            clean -> true
            else -> null
        },
        permissionDenied = false,
        details = detail,
    )
}

internal enum class EvidenceSource(
    val label: String,
) {
    DEDICATED_CARRIER("dedicated app_zygote carrier"),
}
