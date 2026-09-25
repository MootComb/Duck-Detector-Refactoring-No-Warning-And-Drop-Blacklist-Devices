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

package com.eltavine.duckdetector.features.virtualization.data.probes

import android.content.Context
import com.eltavine.duckdetector.features.virtualization.data.rules.VirtualizationHostAppsCatalog
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignal
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalGroup
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity
import java.io.File

data class DexPathProbeResult(
    val classPathEntries: List<String> = emptyList(),
    val entryCount: Int = 0,
    val hitCount: Int = 0,
    val signals: List<VirtualizationSignal> = emptyList(),
    val sourceDir: String = "",
    val splitSourceDirs: List<String> = emptyList(),
    val hostPathHit: Boolean = false,
)

open class DexPathProbe(
    context: Context? = null,
    classLoaderProvider: () -> ClassLoader? = {
        context?.applicationContext?.classLoader ?: Thread.currentThread().contextClassLoader
    },
) {
    private val collector = DexPathCollector(context, classLoaderProvider)

    open fun probe(): DexPathProbeResult {
        val observation = collector.collect() ?: return DexPathProbeResult()
        return evaluate(observation)
    }

    internal fun evaluate(
        entries: List<String>,
        sourceDir: String,
        splitSourceDirs: List<String>,
        packageName: String,
    ): DexPathProbeResult = evaluate(
        collector.observe(
            entries = entries,
            sourceDir = sourceDir,
            splitSourceDirs = splitSourceDirs,
            packageName = packageName,
        ),
    )

    private fun evaluate(observation: DexPathObservation): DexPathProbeResult {
        val normalizedEntries = observation.classPathEntries
        val ownPaths = buildSet {
            observation.sourceDir.takeIf { it.isNotBlank() }?.let(::add)
            observation.splitSourceDirs.forEach(::add)
        }
        val hostSignals = mutableListOf<VirtualizationSignal>()
        val prependSignals = mutableListOf<VirtualizationSignal>()
        val otherUnexpectedEntries = mutableListOf<String>()

        val firstOwnIndex = normalizedEntries.indexOfFirst { it in ownPaths }
        normalizedEntries.forEachIndexed { index, entry ->
            if (entry in ownPaths) {
                return@forEachIndexed
            }
            val hostTarget = VirtualizationHostAppsCatalog.findHostPackageInText(entry)
            if (hostTarget != null || VirtualizationHostAppsCatalog.containsHostToken(entry)) {
                val displayValue = hostTarget?.appName ?: "Host token"
                hostSignals += VirtualizationSignal(
                    id = "virt_dex_host_${entry.stableId()}",
                    label = "Host dex path",
                    value = displayValue,
                    group = VirtualizationSignalGroup.RUNTIME,
                    severity = VirtualizationSignalSeverity.DANGER,
                    detail = entry,
                    detailMonospace = true,
                )
                return@forEachIndexed
            }

            val looksLikeDexContainer = entry.endsWith(".apk") ||
                    entry.endsWith(".jar") ||
                    entry.endsWith(".dex") ||
                    entry.endsWith(".zip")
            if (!looksLikeDexContainer) {
                return@forEachIndexed
            }

            if (firstOwnIndex >= 0 && index < firstOwnIndex) {
                prependSignals += VirtualizationSignal(
                    id = "virt_dex_prepend_${entry.stableId()}",
                    label = "Prepended third-party dex",
                    value = File(entry).name.ifBlank { "Third-party entry" },
                    group = VirtualizationSignalGroup.RUNTIME,
                    severity = VirtualizationSignalSeverity.DANGER,
                    detail = entry,
                    detailMonospace = true,
                )
            } else {
                otherUnexpectedEntries += entry
            }
        }

        val missingOwnPaths = ownPaths.filterNot { it in normalizedEntries }
        val mismatchDetail = buildString {
            if (missingOwnPaths.isNotEmpty()) {
                append("Missing from classloader:\n")
                append(missingOwnPaths.joinToString(separator = "\n"))
            }
            if (otherUnexpectedEntries.isNotEmpty()) {
                if (isNotEmpty()) append("\n\n")
                append("Unexpected classpath entries:\n")
                append(otherUnexpectedEntries.joinToString(separator = "\n"))
            }
        }
        val normalizedSourceDir = observation.sourceDir
        val ownSourceMissing =
            normalizedSourceDir.isNotBlank() && normalizedSourceDir !in normalizedEntries
        val mismatchSeverity = when {
            ownSourceMissing -> VirtualizationSignalSeverity.DANGER
            hostSignals.isNotEmpty() -> VirtualizationSignalSeverity.DANGER
            else -> VirtualizationSignalSeverity.WARNING
        }
        val mismatchSignal = if (mismatchDetail.isNotBlank()) {
            listOf(
                VirtualizationSignal(
                    id = "virt_dex_mismatch",
                    label = "Classpath/source mismatch",
                    value = "Review",
                    group = VirtualizationSignalGroup.CONSISTENCY,
                    severity = mismatchSeverity,
                    detail = mismatchDetail,
                    detailMonospace = true,
                ),
            )
        } else {
            emptyList()
        }

        val signals = (hostSignals + prependSignals + mismatchSignal)
            .distinctBy { it.id }

        return DexPathProbeResult(
            classPathEntries = normalizedEntries,
            entryCount = normalizedEntries.size,
            hitCount = signals.count {
                it.severity == VirtualizationSignalSeverity.DANGER ||
                        it.severity == VirtualizationSignalSeverity.WARNING
            },
            signals = signals,
            sourceDir = normalizedSourceDir,
            splitSourceDirs = observation.splitSourceDirs,
            hostPathHit = hostSignals.isNotEmpty(),
        )
    }

    private fun String.stableId(): String = hashCode().toUInt().toString(16)
}
