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
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckFindingKind
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckMethod
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckMethodOutcome
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckMethodResult
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
        val dangerById = dangerFindings.associateBy { it.kind }
        val infoById = infoFindings.associateBy { it.kind }

        return listOf(
            buildNamingMethod(KernelCheckMethod.EMOJI_SCAN, dangerById[KernelCheckFindingKind.EMOJI]),
            buildNamingMethod(KernelCheckMethod.CHINESE_SCAN, dangerById[KernelCheckFindingKind.CHINESE_CHARS]),
            buildNamingMethod(KernelCheckMethod.SCRIPT_SCAN, dangerById[KernelCheckFindingKind.NON_LATIN_SCRIPTS]),
            buildNamingMethod(KernelCheckMethod.TELEGRAM_SCAN, dangerById[KernelCheckFindingKind.TELEGRAM_REF]),
            buildNamingMethod(KernelCheckMethod.MENTION_SCAN, dangerById[KernelCheckFindingKind.AT_MENTION]),
            buildNamingMethod(KernelCheckMethod.CUSTOM_KERNEL, dangerById[KernelCheckFindingKind.CUSTOM_KERNEL]),
            buildNamingMethod(KernelCheckMethod.KERNEL_VERSION_CHECK, dangerById[KernelCheckFindingKind.NON_RELEASE_KERNEL_VERSION]),
            buildIdentityConsistencyMethod(
                dangerById[KernelCheckFindingKind.KERNEL_IDENTITY_MISMATCH],
                comparedIdentityFields,
            ),
            cpuIdentityMethod,
            buildNativeMethod(
                KernelCheckMethod.CMDLINE_CHECK,
                dangerById[KernelCheckFindingKind.SUSPICIOUS_CMDLINE],
                nativeAvailable,
                "Normal"
            ),
            buildCveMethod(KernelCheckMethod.CVE_PATCH_CHECK, cveAssessment),
            buildInfoMethod(
                KernelCheckMethod.KPTR_RESTRICT,
                infoById[KernelCheckFindingKind.KPTR_EXPOSED],
                unavailable = !nativeAvailable
            ),
            KernelCheckMethodResult(
                method = KernelCheckMethod.NATIVE_LIBRARY,
                summary = if (nativeAvailable) "Loaded" else "Unavailable",
                outcome = if (nativeAvailable) KernelCheckMethodOutcome.CLEAN else KernelCheckMethodOutcome.SUPPORT,
            ),
        )
    }

    private fun buildNamingMethod(
        method: KernelCheckMethod,
        finding: KernelCheckFinding?,
    ): KernelCheckMethodResult {
        return KernelCheckMethodResult(
            method = method,
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
                method = KernelCheckMethod.IDENTITY_CONSISTENCY,
                summary = finding.value,
                outcome = KernelCheckMethodOutcome.DETECTED,
                detail = finding.detail,
            )

            comparedFields.isNotEmpty() -> KernelCheckMethodResult(
                method = KernelCheckMethod.IDENTITY_CONSISTENCY,
                summary = "${comparedFields.sumOf { (_, reads) -> reads.size }} reads agree",
                outcome = KernelCheckMethodOutcome.CLEAN,
                detail = comparedFields.joinToString(separator = "\n") { (field, fieldReads) ->
                    "${field.label}: ${fieldReads.joinToString { it.label }}"
                },
            )

            else -> KernelCheckMethodResult(
                method = KernelCheckMethod.IDENTITY_CONSISTENCY,
                summary = "Unavailable",
                outcome = KernelCheckMethodOutcome.SUPPORT,
                detail = "No kernel identity field had two readable sources, so nothing could be cross-checked.",
            )
        }
    }

    private fun buildNativeMethod(
        method: KernelCheckMethod,
        finding: KernelCheckFinding?,
        nativeAvailable: Boolean,
        cleanSummary: String,
    ): KernelCheckMethodResult {
        return when {
            finding != null -> KernelCheckMethodResult(
                method = method,
                summary = finding.value,
                outcome = KernelCheckMethodOutcome.DETECTED,
                detail = finding.detail,
            )

            nativeAvailable -> KernelCheckMethodResult(
                method = method,
                summary = cleanSummary,
                outcome = KernelCheckMethodOutcome.CLEAN,
            )

            else -> KernelCheckMethodResult(
                method = method,
                summary = "Unavailable",
                outcome = KernelCheckMethodOutcome.SUPPORT,
            )
        }
    }

    private fun buildCveMethod(
        method: KernelCheckMethod,
        assessment: CvePatchAssessment,
    ): KernelCheckMethodResult {
        return KernelCheckMethodResult(
            method = method,
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
        method: KernelCheckMethod,
        finding: KernelCheckFinding?,
        unavailable: Boolean = false,
    ): KernelCheckMethodResult {
        return when {
            finding != null -> KernelCheckMethodResult(
                method = method,
                summary = finding.value,
                outcome = KernelCheckMethodOutcome.INFO,
                detail = finding.detail,
            )

            unavailable -> KernelCheckMethodResult(
                method = method,
                summary = "Unavailable",
                outcome = KernelCheckMethodOutcome.SUPPORT,
            )

            else -> KernelCheckMethodResult(
                method = method,
                summary = "OK",
                outcome = KernelCheckMethodOutcome.CLEAN,
            )
        }
    }
}
