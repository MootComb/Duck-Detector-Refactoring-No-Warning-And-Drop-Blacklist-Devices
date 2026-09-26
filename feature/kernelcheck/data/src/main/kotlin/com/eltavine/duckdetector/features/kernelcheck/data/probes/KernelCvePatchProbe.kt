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

package com.eltavine.duckdetector.features.kernelcheck.data.probes

import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckCvePatchState
import java.util.concurrent.TimeUnit

/**
 * Checks whether Android/data can still be listed through paths that embed ignorable Unicode
 * codepoints, the path filter bypass the report labels CVE-2024-43093.
 */
internal object KernelCvePatchProbe {
    private const val UNICODE_TEST_TIMEOUT_SECONDS = 2L

    fun detectCvePatchState(): CvePatchAssessment {
        val targetPath = "/sdcard/Android/data"
        val zwcProbe = testUnicodeBypass(
            basePath = targetPath,
            bypassChar = "\u200B",
            bypassName = "Zero Width Space",
        )
        val otherIgnorableChars = listOf(
            "\u00AD" to "Soft Hyphen",
            "\u034F" to "Combining Grapheme Joiner",
            "\u200C" to "Zero Width Non-Joiner",
            "\u200D" to "Zero Width Joiner",
            "\u2060" to "Word Joiner",
            "\uFEFF" to "BOM/ZWNBSP",
            "\u180E" to "Mongolian Vowel Separator",
        )

        val otherProbes = otherIgnorableChars.map { (char, name) ->
            char to testUnicodeBypass(
                basePath = targetPath,
                bypassChar = char,
                bypassName = name,
            )
        }
        val workingProbe = otherProbes.firstOrNull { (_, probe) ->
            probe.state == UnicodeBypassState.BYPASSED
        }
        val inconclusiveProbe = otherProbes.firstOrNull { (_, probe) ->
            probe.state == UnicodeBypassState.INCONCLUSIVE
        }?.second

        return when {
            zwcProbe.state == UnicodeBypassState.BYPASSED && workingProbe != null -> {
                val (char, probe) = workingProbe
                CvePatchAssessment(
                    state = KernelCheckCvePatchState.UNPATCHED,
                    detail = buildString {
                        append("ZWC and ")
                        append(probe.bypassName)
                        append(" (U+")
                        append(char.codePointAt(0).toString(16).uppercase())
                        append(") still bypass the path filter.")
                    },
                )
            }

            zwcProbe.state == UnicodeBypassState.BLOCKED && workingProbe != null -> {
                val (char, probe) = workingProbe
                CvePatchAssessment(
                    state = KernelCheckCvePatchState.PARTIALLY_PATCHED,
                    detail = buildString {
                        append("ZWC is blocked, but ")
                        append(probe.bypassName)
                        append(" (U+")
                        append(char.codePointAt(0).toString(16).uppercase())
                        append(") still bypasses the path filter.")
                    },
                )
            }

            zwcProbe.state == UnicodeBypassState.BLOCKED &&
                    otherProbes.all { (_, probe) -> probe.state == UnicodeBypassState.BLOCKED } -> {
                CvePatchAssessment(
                    state = KernelCheckCvePatchState.PATCHED,
                    detail = "ZWC and ${otherProbes.size} tested ignorable codepoints were blocked.",
                )
            }

            zwcProbe.state == UnicodeBypassState.BYPASSED &&
                    otherProbes.all { (_, probe) -> probe.state == UnicodeBypassState.BLOCKED } -> {
                CvePatchAssessment(
                    state = KernelCheckCvePatchState.INCONCLUSIVE,
                    detail = "ZWC bypassed, but the other tested ignorable codepoints did not. The result does not fit a stable patched or unpatched pattern.",
                )
            }

            zwcProbe.state == UnicodeBypassState.INCONCLUSIVE -> {
                CvePatchAssessment(
                    state = KernelCheckCvePatchState.INCONCLUSIVE,
                    detail = zwcProbe.detail
                        ?: "The ZWC bypass probe could not produce a stable result.",
                )
            }

            inconclusiveProbe != null -> {
                CvePatchAssessment(
                    state = KernelCheckCvePatchState.INCONCLUSIVE,
                    detail = inconclusiveProbe.detail
                        ?: "One or more ignorable-codepoint probes could not produce a stable result.",
                )
            }

            else -> {
                CvePatchAssessment(
                    state = KernelCheckCvePatchState.INCONCLUSIVE,
                    detail = "The bypass probes did not produce enough stable evidence to determine patch state.",
                )
            }
        }
    }

    private fun testUnicodeBypass(
        basePath: String,
        bypassChar: String,
        bypassName: String,
    ): UnicodeBypassProbe {
        val baseProbe = runListProbe("$basePath/")
        if (baseProbe.succeeded) {
            return UnicodeBypassProbe(
                state = UnicodeBypassState.INCONCLUSIVE,
                bypassName = bypassName,
                detail = "The base Android/data path is directly listable, so bypass status cannot be inferred from this probe.",
            )
        }

        val bypassPaths = listOf(
            "$basePath$bypassChar/",
            "$basePath/$bypassChar",
        )

        var hadCompletedAttempt = false
        bypassPaths.forEach { bypassPath ->
            val probe = runListProbe(bypassPath)
            if (probe.completed) {
                hadCompletedAttempt = true
            }
            if (probe.succeeded) {
                return UnicodeBypassProbe(
                    state = UnicodeBypassState.BYPASSED,
                    bypassName = bypassName,
                    detail = "$bypassName successfully bypassed the path filter.",
                )
            }
        }

        return if (hadCompletedAttempt) {
            UnicodeBypassProbe(
                state = UnicodeBypassState.BLOCKED,
                bypassName = bypassName,
                detail = "$bypassName was blocked by the path filter.",
            )
        } else {
            UnicodeBypassProbe(
                state = UnicodeBypassState.INCONCLUSIVE,
                bypassName = bypassName,
                detail = "The $bypassName probe could not execute reliably.",
            )
        }
    }

    private fun runListProbe(
        path: String,
    ): DirectoryListProbe {
        var process: Process? = null
        return try {
            process = ProcessBuilder("ls", path)
                .redirectErrorStream(true)
                .start()
            process.inputStream.bufferedReader().use { it.readText() }
            if (!process.waitFor(UNICODE_TEST_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                DirectoryListProbe(
                    completed = false,
                    exitCode = null,
                )
            } else {
                DirectoryListProbe(
                    completed = true,
                    exitCode = process.exitValue(),
                )
            }
        } catch (_: Exception) {
            DirectoryListProbe(
                completed = false,
                exitCode = null,
            )
        } finally {
            process?.destroy()
        }
    }
}

internal data class CvePatchAssessment(
    val state: KernelCheckCvePatchState,
    val detail: String,
)

internal data class UnicodeBypassProbe(
    val state: UnicodeBypassState,
    val bypassName: String,
    val detail: String? = null,
)

internal data class DirectoryListProbe(
    val completed: Boolean,
    val exitCode: Int?,
) {
    val succeeded: Boolean
        get() = completed && exitCode == 0
}

internal enum class UnicodeBypassState {
    BYPASSED,
    BLOCKED,
    INCONCLUSIVE,
}
