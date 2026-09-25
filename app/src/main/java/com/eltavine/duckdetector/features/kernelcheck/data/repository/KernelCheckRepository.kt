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

import com.eltavine.duckdetector.features.kernelcheck.data.native.KernelCheckNativeBridge
import com.eltavine.duckdetector.features.kernelcheck.data.native.KernelCheckNativeSnapshot
import com.eltavine.duckdetector.features.kernelcheck.data.probes.KernelCvePatchProbe
import com.eltavine.duckdetector.features.kernelcheck.data.rules.Arm64CpuIdentityConsistencyEvaluator
import com.eltavine.duckdetector.features.kernelcheck.data.rules.KernelIdentityRules
import com.eltavine.duckdetector.features.kernelcheck.data.rules.KernelIdentityScripts
import com.eltavine.duckdetector.features.kernelcheck.data.utils.KernelIdentityConsistencyUtils
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckFinding
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckCvePatchState
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckFindingSeverity
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckReport
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckStage
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelIdentityRead
import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class KernelCheckRepository(
    private val nativeBridge: KernelCheckNativeBridge = KernelCheckNativeBridge(),
    private val identityConsistencyUtils: KernelIdentityConsistencyUtils =
        KernelIdentityConsistencyUtils(),
    private val cpuIdentityEvaluator: Arm64CpuIdentityConsistencyEvaluator =
        Arm64CpuIdentityConsistencyEvaluator(),
) {

    suspend fun scan(): KernelCheckReport = withContext(Dispatchers.IO) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                KernelCheckReport.failed(throwable.message ?: "Kernel Check scan failed.")
            }
    }

    private fun scanInternal(): KernelCheckReport {
        val unameOutput = getUnameOutput()
        val nativeSnapshot = nativeBridge.collectSnapshot()
        val procVersion = nativeSnapshot.procVersion.ifBlank { readFileText("/proc/version") }
        val procCmdline = nativeSnapshot.procCmdline.ifBlank {
            readFileText("/proc/cmdline").replace(
                '\u0000',
                ' '
            )
        }
        val identitySources = listOf(unameOutput, procVersion)
            .filter { it.isNotBlank() }
            .distinct()

        if (identitySources.isEmpty() && procCmdline.isBlank() && !nativeSnapshot.available) {
            return KernelCheckReport.failed(
                nativeSnapshot.collection.explain(
                    "Unable to read kernel identity through uname -a or /proc/version",
                ),
            )
        }

        val dangerFindings = mutableListOf<KernelCheckFinding>()
        val infoFindings = mutableListOf<KernelCheckFinding>()
        val combinedIdentity = identitySources.joinToString(separator = "\n")

        val emojis = KernelIdentityScripts.findEmojis(combinedIdentity)
        if (emojis.isNotEmpty()) {
            dangerFindings += KernelCheckFinding(
                id = "emoji",
                label = "Emoji markers",
                value = emojis.joinToString(" "),
                detail = "Kernel identity contains emoji codepoints.",
                severity = KernelCheckFindingSeverity.HARD,
            )
        }

        val chineseChars = KernelIdentityScripts.findChineseCharacters(combinedIdentity)
        if (chineseChars.isNotEmpty()) {
            dangerFindings += KernelCheckFinding(
                id = "chinese_chars",
                label = "Chinese glyphs",
                value = chineseChars.joinToString(""),
                detail = "Kernel identity contains CJK characters.",
                severity = KernelCheckFindingSeverity.HARD,
            )
        }

        val nonLatinScriptResult = KernelIdentityScripts.findNonLatinScriptCharacters(combinedIdentity)
        if (nonLatinScriptResult.samples.isNotEmpty()) {
            dangerFindings += KernelCheckFinding(
                id = "non_latin_scripts",
                label = "Other language scripts",
                value = nonLatinScriptResult.scriptNames.joinToString(", "),
                detail = buildString {
                    append("Kernel identity contains non-Latin script characters")
                    if (nonLatinScriptResult.scriptNames.isNotEmpty()) {
                        append(": ")
                        append(nonLatinScriptResult.scriptNames.joinToString(", "))
                    }
                    if (nonLatinScriptResult.samples.isNotEmpty()) {
                        append(". Samples: ")
                        append(nonLatinScriptResult.samples.joinToString(" "))
                    }
                    append(".")
                },
                severity = KernelCheckFindingSeverity.HARD,
            )
        }

        val telegramMatches = KernelIdentityRules.TELEGRAM_REGEX.findAll(combinedIdentity)
            .map { it.value }
            .distinct()
            .toList()
        if (telegramMatches.isNotEmpty()) {
            dangerFindings += KernelCheckFinding(
                id = "telegram_ref",
                label = "Telegram reference",
                value = telegramMatches.joinToString(", "),
                detail = "Kernel identity references TG/Telegram style handles or channels.",
                severity = KernelCheckFindingSeverity.HARD,
            )
        }

        val mentionMatches = KernelIdentityRules.MENTION_REGEX.findAll(combinedIdentity)
            .map { it.value }
            .distinct()
            .toList()
        if (mentionMatches.isNotEmpty()) {
            dangerFindings += KernelCheckFinding(
                id = "at_mention",
                label = "@ mentions",
                value = mentionMatches.joinToString(", "),
                detail = "Kernel identity contains maintainer-style @ mentions.",
                severity = KernelCheckFindingSeverity.HARD,
            )
        }

        val customKeywords = KernelIdentityRules.detectCustomKernelKeywords(combinedIdentity)
        if (customKeywords.isNotEmpty()) {
            dangerFindings += KernelCheckFinding(
                id = "custom_kernel",
                label = "Custom identifiers",
                value = customKeywords.joinToString(", "),
                detail = "Known community kernel identifiers matched the kernel identity.",
                severity = KernelCheckFindingSeverity.HARD,
            )
        }

        val nonReleaseMajorVersion = KernelIdentityRules.detectNonReleaseKernelMajorVersion(unameOutput)
        if (nonReleaseMajorVersion != null) {
            dangerFindings += KernelCheckFinding(
                id = "non_release_kernel_version",
                label = "Kernel major version",
                value = nonReleaseMajorVersion,
                detail = "Kernel release major version $nonReleaseMajorVersion does not match any " +
                        "released Linux kernel major version.",
                severity = KernelCheckFindingSeverity.HARD,
            )
        }

        val identityReads = collectIdentityReads(nativeSnapshot, procVersion)
        val identityMismatch = identityConsistencyUtils.detectMismatch(identityReads)
        if (identityMismatch != null) {
            dangerFindings += identityMismatch
        }

        val cpuIdentityAssessment = cpuIdentityEvaluator.evaluate(
            status = nativeSnapshot.cpuIdentityStatus,
            observations = nativeSnapshot.cpuIdentityObservations,
        )
        cpuIdentityAssessment.finding?.let(dangerFindings::add)

        val cmdlineMatches = nativeSnapshot.findings.details("CMDLINE|CRITICAL|")
            .ifEmpty { KernelIdentityRules.detectCriticalCmdlineFallback(procCmdline) }
        if (cmdlineMatches.isNotEmpty()) {
            dangerFindings += KernelCheckFinding(
                id = "suspicious_cmdline",
                label = "Boot cmdline",
                value = "${cmdlineMatches.size} hit(s)",
                detail = cmdlineMatches.joinToString(separator = "\n"),
                severity = KernelCheckFindingSeverity.HARD,
            )
        }

        val kptrDetail = nativeSnapshot.findings.firstDetail("KPTR_RESTRICT|DISABLED|")
        if (kptrDetail != null || nativeSnapshot.kptrExposed) {
            infoFindings += KernelCheckFinding(
                id = "kptr_exposed",
                label = "Kernel pointers",
                value = "Exposed",
                detail = kptrDetail ?: "kptr_restrict appears disabled.",
                severity = KernelCheckFindingSeverity.INFO,
            )
        }

        val cveAssessment = KernelCvePatchProbe.detectCvePatchState()
        if (cveAssessment.state == KernelCheckCvePatchState.UNPATCHED ||
            cveAssessment.state == KernelCheckCvePatchState.PARTIALLY_PATCHED
        ) {
            infoFindings += KernelCheckFinding(
                id = "cve_patch_state",
                label = "CVE-2024-43093",
                value = cveAssessment.state.label,
                detail = cveAssessment.detail,
                severity = KernelCheckFindingSeverity.INFO,
            )
        }

        val methods = KernelCheckMethods.buildMethods(
            dangerFindings = dangerFindings,
            infoFindings = infoFindings,
            cveAssessment = cveAssessment,
            nativeAvailable = nativeSnapshot.available,
            comparedIdentityFields = identityConsistencyUtils.comparedFields(identityReads),
            cpuIdentityMethod = cpuIdentityAssessment.method,
        )

        return KernelCheckReport(
            stage = KernelCheckStage.READY,
            unameOutput = unameOutput,
            procVersion = procVersion,
            procCmdline = procCmdline,
            dangerFindings = dangerFindings,
            infoFindings = infoFindings,
            suspiciousCmdline = cmdlineMatches.isNotEmpty(),
            kptrExposed = kptrDetail != null || nativeSnapshot.kptrExposed,
            cvePatchState = cveAssessment.state,
            cvePatchDetail = cveAssessment.detail,
            nativeAvailable = nativeSnapshot.available,
            checkedKeywordCount = KernelIdentityRules.KEYWORD_SCAN_COUNT,
            checkedCmdlineRuleCount = KernelIdentityRules.CMDLINE_CHECKS.size,
            methods = methods,
            identityReads = identityReads,
        )
    }

    private fun collectIdentityReads(
        nativeSnapshot: KernelCheckNativeSnapshot,
        procVersion: String,
    ): List<KernelIdentityRead> {
        return identityConsistencyUtils.buildReads(
            jvmOsVersion = System.getProperty("os.version").orEmpty(),
            unameSyscallRelease = nativeSnapshot.utsRelease,
            unameSyscallVersion = nativeSnapshot.utsVersion,
            unameCommandRelease = executeCommand("uname", "-r"),
            sysctlOsRelease = nativeSnapshot.sysctlOsRelease
                .ifBlank { readFileText("/proc/sys/kernel/osrelease") },
            sysctlVersion = nativeSnapshot.sysctlVersion
                .ifBlank { readFileText("/proc/sys/kernel/version") },
            procVersion = procVersion,
        )
    }

    private fun getUnameOutput(): String {
        return executeCommand("uname", "-a")
            .ifBlank { readFileText("/proc/version") }
    }

    private fun executeCommand(
        vararg command: String,
    ): String {
        var process: Process? = null
        return try {
            process = ProcessBuilder(*command)
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().use { it.readText().trim() }
            if (!process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                ""
            } else {
                output
            }
        } catch (_: Exception) {
            ""
        } finally {
            process?.destroy()
        }
    }

    private fun readFileText(
        path: String,
    ): String {
        return try {
            val file = File(path)
            if (!file.exists() || !file.canRead()) {
                ""
            } else {
                file.readText().trim().replace('\u0000', ' ')
            }
        } catch (_: Exception) {
            ""
        }
    }

    private fun List<String>.firstDetail(
        prefix: String,
    ): String? {
        return firstOrNull { it.startsWith(prefix) }?.substringAfter(prefix)
            ?.takeIf { it.isNotBlank() }
    }

    private fun List<String>.details(
        prefix: String,
    ): List<String> {
        return filter { it.startsWith(prefix) }
            .mapNotNull { it.substringAfter(prefix).takeIf { detail -> detail.isNotBlank() } }
    }

    companion object {
        private const val PROCESS_TIMEOUT_SECONDS = 2L
    }
}
