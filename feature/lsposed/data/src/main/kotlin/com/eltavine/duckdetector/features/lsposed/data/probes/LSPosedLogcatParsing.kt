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

package com.eltavine.duckdetector.features.lsposed.data.probes

import com.eltavine.duckdetector.features.lsposed.domain.LSPosedProbe
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity

internal fun parseOverview(
    output: String,
    emittedIds: MutableSet<String>,
): List<LSPosedSignal> {
    if (output.isBlank()) {
        return emptyList()
    }

    val signals = mutableListOf<LSPosedSignal>()
    meaningfulLines(output).forEach { line ->
        val tag = Regex("""^[VDIWEF]/([^(]+)\(""")
            .find(line)
            ?.groupValues
            ?.getOrNull(1)
            ?.trim()

        tag?.let { currentTag ->
            LSPosedProbeSupport.logcatTags.firstOrNull { knownTag ->
                currentTag.equals(knownTag, ignoreCase = true) ||
                        currentTag.contains(knownTag, ignoreCase = true)
            }?.let { matchedTag ->
                val signalId = "logcat_tag_${matchedTag.toSignalIdSegment()}"
                if (emittedIds.add(signalId)) {
                    signals += dangerSignal(
                        id = signalId,
                        label = "Logcat tag",
                        value = currentTag,
                        detail = line.trimToPreview(),
                    )
                }
            }

            LSPosedProbeSupport.logcatTagPrefixes.firstOrNull { prefix ->
                currentTag.startsWith(prefix, ignoreCase = true)
            }?.let { matchedPrefix ->
                val signalId =
                    "logcat_prefix_${matchedPrefix.toSignalIdSegment()}_${currentTag.toSignalIdSegment()}"
                if (emittedIds.add(signalId)) {
                    signals += dangerSignal(
                        id = signalId,
                        label = "Logcat tag prefix",
                        value = currentTag,
                        detail = line.trimToPreview(),
                    )
                }
            }
        }

        LSPosedProbeSupport.logcatPatterns.forEach { pattern ->
            if (!line.matchesPattern(pattern)) {
                return@forEach
            }

            val signalId = "logcat_pattern_${pattern.toSignalIdSegment()}"
            if (emittedIds.add(signalId)) {
                val strong = pattern.startsWith("!!")
                signals += LSPosedSignal(
                    id = signalId,
                    probe = LSPosedProbe.LOGCAT,
                    label = "Logcat pattern",
                    value = pattern,
                    group = LSPosedSignalGroup.RUNTIME,
                    severity = if (strong) LSPosedSignalSeverity.DANGER else LSPosedSignalSeverity.WARNING,
                    detail = line.trimToPreview(),
                    detailMonospace = true,
                )
            }
        }

        if (line.isSelinuxAvcLine()) {
            return@forEach
        }

        val lowerLine = line.lowercase()
        if (
            lowerLine.contains("lsposed") ||
            lowerLine.contains("lspd") ||
            (lowerLine.contains("xposed") && lowerLine.contains("bridge"))
        ) {
            val signalId = "logcat_direct_${line.take(48).toSignalIdSegment()}"
            if (emittedIds.add(signalId)) {
                signals += dangerSignal(
                    id = signalId,
                    label = "Logcat direct hit",
                    value = "Direct",
                    detail = line.trimToPreview(),
                )
            }
        }
    }

    return signals
}

internal fun parseTagOutput(
    id: String,
    output: String,
    emittedIds: MutableSet<String>,
): List<LSPosedSignal> {
    val lines = meaningfulLines(output)
    if (lines.isEmpty()) {
        return emptyList()
    }

    val tag = id.removePrefix(TAG_COMMAND_PREFIX)
    val signalId = "logcat_filter_${tag.toSignalIdSegment()}"
    if (!emittedIds.add(signalId)) {
        return emptyList()
    }

    return listOf(
        dangerSignal(
            id = signalId,
            label = "Logcat tag filter",
            value = "${lines.size} line(s)",
            detail = buildString {
                appendLine("Tag: $tag")
                lines.take(6).forEach { line -> appendLine(line.trimToPreview()) }
            }.trim(),
        ),
    )
}

internal fun parseProcessOutput(
    output: String,
    emittedIds: MutableSet<String>,
): List<LSPosedSignal> {
    val line = meaningfulLines(output).firstOrNull { entry ->
        entry.contains("org.lsposed.daemon", ignoreCase = true) ||
                entry.contains("lsposed daemon", ignoreCase = true)
    } ?: return emptyList()

    val signalId = "logcat_process_lsposed_daemon"
    if (!emittedIds.add(signalId)) {
        return emptyList()
    }

    return listOf(
        dangerSignal(
            id = signalId,
            label = "Logcat process",
            value = "org.lsposed.daemon",
            detail = line.trimToPreview(),
        ),
    )
}

private fun meaningfulLines(
    output: String,
): List<String> {
    return output.lineSequence()
        .map { it.trim() }
        .filter { it.isNotBlank() }
        .filterNot { it.startsWith("---------") }
        .filterNot(::shouldExcludeLine)
        .toList()
}

private fun shouldExcludeLine(
    line: String,
): Boolean {
    val lower = line.lowercase()
    if (SELINUX_AUDIT_MARKER in lower) {
        return true
    }
    if (line.isDirtyPolicyLsposedFileAvc()) {
        return true
    }
    return LSPosedProbeSupport.runtimeExcludePatterns.any { token -> lower.contains(token) }
}

private fun String.isDirtyPolicyLsposedFileAvc(): Boolean {
    val lower = lowercase()
    return "avc:" in lower &&
            "denied" in lower &&
            "scontext=u:r:untrusted_app" in lower &&
            "tcontext=u:object_r:lsposed_file:s0" in lower &&
            "tclass=file" in lower &&
            DIRTY_POLICY_LSPOSED_FILE_READ_REGEX.containsMatchIn(this)
}

private fun String.isSelinuxAvcLine(): Boolean {
    val lower = lowercase()
    return "avc:" in lower &&
            "denied" in lower &&
            "scontext=" in lower &&
            "tcontext=" in lower
}

private fun String.matchesPattern(
    pattern: String,
): Boolean {
    val lowerLine = lowercase()
    val lowerPattern = pattern.lowercase()
    if (!lowerLine.contains(lowerPattern)) {
        return false
    }

    val isControlMessage = pattern.startsWith("!!")
    val isLsposedSpecific = pattern.contains("SystemClassLoader") ||
            pattern.contains("InMemoryDexClassLoader") ||
            pattern.contains("ObfuscationManager") ||
            pattern.contains("startBootstrapHook") ||
            pattern.contains("LoadedApk#")

    return isControlMessage ||
            isLsposedSpecific ||
            lowerLine.contains("xposed") ||
            lowerLine.contains("lsposed") ||
            lowerLine.contains("module")
}

private fun dangerSignal(
    id: String,
    label: String,
    value: String,
    detail: String,
): LSPosedSignal {
    return LSPosedSignal(
        id = id,
        probe = LSPosedProbe.LOGCAT,
        label = label,
        value = value,
        group = LSPosedSignalGroup.RUNTIME,
        severity = LSPosedSignalSeverity.DANGER,
        detail = detail,
        detailMonospace = true,
    )
}

internal const val TAG_COMMAND_PREFIX = "tag:"

private const val SELINUX_AUDIT_MARKER = "duckdetector_probe="

private val DIRTY_POLICY_LSPOSED_FILE_READ_REGEX =
    Regex("""avc:\s*denied\s*\{\s*read\s*\}""", RegexOption.IGNORE_CASE)
