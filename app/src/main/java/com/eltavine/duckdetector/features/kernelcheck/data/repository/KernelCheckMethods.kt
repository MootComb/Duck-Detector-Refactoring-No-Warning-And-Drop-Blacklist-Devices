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

package com.eltavine.duckdetector.features.kernelcheck.data.repository

import com.eltavine.duckdetector.features.kernelcheck.data.probes.CvePatchAssessment
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckCvePatchState
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckFinding
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckMethodOutcome
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckMethodResult
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckReport
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelIdentityField
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelIdentityRead

/** Turns the collected findings into the per-method results the report lists. */
internal object KernelCheckMethods {
    fun buildMethods(
        dangerFindings: List<KernelCheckFinding>,
        infoFindings: List<KernelCheckFinding>,
        cveAssessment: CvePatchAssessment,
        nativeAvailable: Boolean,
        comparedIdentityFields: List<Pair<KernelIdentityField, List<KernelIdentityRead>>>,
        cpuIdentityMethod: KernelCheckMethodResult,
    ): List<KernelCheckMethodResult> {
        val dangerById = dangerFindings.associateBy { it.id }
        val infoById = infoFindings.associateBy { it.id }

        return listOf(
            buildNamingMethod("emojiScan", dangerById["emoji"]),
            buildNamingMethod("chineseScan", dangerById["chinese_chars"]),
            buildNamingMethod("scriptScan", dangerById["non_latin_scripts"]),
            buildNamingMethod("telegramScan", dangerById["telegram_ref"]),
            buildNamingMethod("mentionScan", dangerById["at_mention"]),
            buildNamingMethod("customKernel", dangerById["custom_kernel"]),
            buildNamingMethod("kernelVersionCheck", dangerById["non_release_kernel_version"]),
            buildIdentityConsistencyMethod(
                dangerById[KernelCheckReport.IDENTITY_MISMATCH_FINDING_ID],
                comparedIdentityFields,
            ),
            cpuIdentityMethod,
            buildNativeMethod(
                "cmdlineCheck",
                dangerById["suspicious_cmdline"],
                nativeAvailable,
                "Normal"
            ),
            buildCveMethod("cvePatchCheck", cveAssessment),
            buildInfoMethod(
                "kptrRestrict",
                infoById["kptr_exposed"],
                unavailable = !nativeAvailable
            ),
            KernelCheckMethodResult(
                label = "nativeLibrary",
                summary = if (nativeAvailable) "Loaded" else "Unavailable",
                outcome = if (nativeAvailable) KernelCheckMethodOutcome.CLEAN else KernelCheckMethodOutcome.SUPPORT,
            ),
        )
    }

    private fun buildNamingMethod(
        label: String,
        finding: KernelCheckFinding?,
    ): KernelCheckMethodResult {
        return KernelCheckMethodResult(
            label = label,
            summary = finding?.value ?: "Clean",
            outcome = if (finding != null) {
                KernelCheckMethodOutcome.DETECTED
            } else {
                KernelCheckMethodOutcome.CLEAN
            },
            detail = finding?.detail,
        )
    }

    private fun buildIdentityConsistencyMethod(
        finding: KernelCheckFinding?,
        comparedFields: List<Pair<KernelIdentityField, List<KernelIdentityRead>>>,
    ): KernelCheckMethodResult {
        return when {
            finding != null -> KernelCheckMethodResult(
                label = "identityConsistency",
                summary = finding.value,
                outcome = KernelCheckMethodOutcome.DETECTED,
                detail = finding.detail,
            )

            comparedFields.isNotEmpty() -> KernelCheckMethodResult(
                label = "identityConsistency",
                summary = "${comparedFields.sumOf { (_, reads) -> reads.size }} reads agree",
                outcome = KernelCheckMethodOutcome.CLEAN,
                detail = comparedFields.joinToString(separator = "\n") { (field, fieldReads) ->
                    "${field.label}: ${fieldReads.joinToString { it.label }}"
                },
            )

            else -> KernelCheckMethodResult(
                label = "identityConsistency",
                summary = "Unavailable",
                outcome = KernelCheckMethodOutcome.SUPPORT,
                detail = "No kernel identity field had two readable sources, so nothing could be cross-checked.",
            )
        }
    }

    private fun buildNativeMethod(
        label: String,
        finding: KernelCheckFinding?,
        nativeAvailable: Boolean,
        cleanSummary: String,
    ): KernelCheckMethodResult {
        return when {
            finding != null -> KernelCheckMethodResult(
                label = label,
                summary = finding.value,
                outcome = KernelCheckMethodOutcome.DETECTED,
                detail = finding.detail,
            )

            nativeAvailable -> KernelCheckMethodResult(
                label = label,
                summary = cleanSummary,
                outcome = KernelCheckMethodOutcome.CLEAN,
            )

            else -> KernelCheckMethodResult(
                label = label,
                summary = "Unavailable",
                outcome = KernelCheckMethodOutcome.SUPPORT,
            )
        }
    }

    private fun buildCveMethod(
        label: String,
        assessment: CvePatchAssessment,
    ): KernelCheckMethodResult {
        return KernelCheckMethodResult(
            label = label,
            summary = assessment.state.label,
            outcome = when (assessment.state) {
                KernelCheckCvePatchState.UNPATCHED,
                KernelCheckCvePatchState.PARTIALLY_PATCHED -> KernelCheckMethodOutcome.INFO

                KernelCheckCvePatchState.PATCHED -> KernelCheckMethodOutcome.CLEAN
                KernelCheckCvePatchState.INCONCLUSIVE -> KernelCheckMethodOutcome.SUPPORT
            },
            detail = assessment.detail,
        )
    }

    private fun buildInfoMethod(
        label: String,
        finding: KernelCheckFinding?,
        unavailable: Boolean = false,
    ): KernelCheckMethodResult {
        return when {
            finding != null -> KernelCheckMethodResult(
                label = label,
                summary = finding.value,
                outcome = KernelCheckMethodOutcome.INFO,
                detail = finding.detail,
            )

            unavailable -> KernelCheckMethodResult(
                label = label,
                summary = "Unavailable",
                outcome = KernelCheckMethodOutcome.SUPPORT,
            )

            else -> KernelCheckMethodResult(
                label = label,
                summary = "OK",
                outcome = KernelCheckMethodOutcome.CLEAN,
            )
        }
    }
}
