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

package com.eltavine.duckdetector.features.mount.data.repository

import com.eltavine.duckdetector.capability.earlypreload.data.EarlyMountPreloadResult
import com.eltavine.duckdetector.capability.earlypreload.data.EarlyMountPreloadSignal
import com.eltavine.duckdetector.features.mount.data.native.MountNativeSnapshot
import com.eltavine.duckdetector.features.mount.domain.MountFinding
import com.eltavine.duckdetector.features.mount.domain.MountFindingGroup
import com.eltavine.duckdetector.features.mount.domain.MountFindingSeverity

internal fun sanitizePreloadResult(
    result: EarlyMountPreloadResult,
    snapshot: MountNativeSnapshot,
): EarlyMountPreloadResult {
    if (!result.mountIdGapDetected || snapshot.mountIdLoopholeDetected) {
        return result
    }

    val mountIdMessages = result.messagesFor(EarlyMountPreloadSignal.MOUNT_ID_GAP)
    if (mountIdMessages.isEmpty() || !mountIdMessages.all(::isWeakDataMirrorMountIdGap)) {
        return result
    }

    val filteredFindings = result.findings.filterNot { finding ->
        val type = finding.substringBefore('|')
        val message = finding.split('|').getOrNull(1).orEmpty()
        type == EarlyMountPreloadSignal.MOUNT_ID_GAP.key && isWeakDataMirrorMountIdGap(message)
    }

    return result.copy(
        detected = false,
        detectionMethod = "",
        details = "",
        mountIdGapDetected = false,
        findings = filteredFindings,
    ).normalize()
}

private fun isWeakDataMirrorMountIdGap(
    message: String,
): Boolean {
    val normalized = message.trim()
    if (SMALL_DATA_MIRROR_SINGLE_MOUNT_ID_REGEX.matches(normalized)) {
        return true
    }

    val match = SMALL_DATA_MIRROR_MULTI_MOUNT_ID_REGEX.matchEntire(normalized) ?: return false
    val missingCount = match.groupValues.getOrNull(1)?.toIntOrNull() ?: return false
    return missingCount <= SMALL_DATA_MIRROR_GAP_THRESHOLD
}

internal fun buildPreloadFindings(result: EarlyMountPreloadResult): List<MountFinding> {
    if (!result.available) {
        return emptyList()
    }

    return buildList {
        if (result.mntStringsDetected) {
            add(
                MountFinding(
                    id = "early_preload_mnt_strings",
                    label = "mntent strings residue",
                    value = result.mntStringsSource.ifBlank {
                        result.mntStringsTarget.ifBlank { "Detected" }
                    },
                    group = MountFindingGroup.ARTIFACTS,
                    severity = MountFindingSeverity.DANGER,
                    detail = preloadSignalDetail(
                        result = result,
                        signal = EarlyMountPreloadSignal.MNT_STRINGS,
                        extras = listOfNotNull(
                            result.mntStringsSource.takeIf { it.isNotBlank() }
                                ?.let { "source=$it" },
                            result.mntStringsTarget.takeIf { it.isNotBlank() }
                                ?.let { "target=$it" },
                            result.mntStringsFs.takeIf { it.isNotBlank() }?.let { "fs=$it" },
                        ),
                    ),
                    detailMonospace = true,
                ),
            )
        }
        if (result.futileHideDetected) {
            add(
                MountFinding(
                    id = "early_preload_futile_hide",
                    label = "Futile hide",
                    value = "ctime drift",
                    group = MountFindingGroup.CONSISTENCY,
                    severity = MountFindingSeverity.DANGER,
                    detail = preloadSignalDetail(
                        result = result,
                        signal = EarlyMountPreloadSignal.FUTILE_HIDE,
                        extras = listOf(
                            "ns/mnt ctime delta=${result.nsMntCtimeDeltaNs}ns",
                            "mountinfo ctime delta=${result.mountInfoCtimeDeltaNs}ns",
                        ),
                    ),
                    detailMonospace = true,
                ),
            )
        }
        if (result.mountIdGapDetected) {
            add(
                MountFinding(
                    id = "early_preload_mount_id_loophole",
                    label = "Mount ID loophole",
                    value = "Startup preload",
                    group = MountFindingGroup.CONSISTENCY,
                    severity = MountFindingSeverity.DANGER,
                    detail = preloadSignalDetail(
                        result = result,
                        signal = EarlyMountPreloadSignal.MOUNT_ID_GAP,
                    ),
                    detailMonospace = true,
                ),
            )
        }
        if (result.minorDevGapDetected) {
            add(
                MountFinding(
                    id = "early_preload_minor_dev_gap",
                    label = "Minor device gap",
                    value = "Sequence drift",
                    group = MountFindingGroup.CONSISTENCY,
                    severity = MountFindingSeverity.WARNING,
                    detail = preloadSignalDetail(
                        result = result,
                        signal = EarlyMountPreloadSignal.MINOR_DEV_GAP,
                    ),
                    detailMonospace = true,
                ),
            )
        }
        if (result.peerGroupGapDetected) {
            add(
                MountFinding(
                    id = "early_preload_peer_group_gap",
                    label = "Peer group gap",
                    value = "Startup gap",
                    group = MountFindingGroup.CONSISTENCY,
                    severity = MountFindingSeverity.WARNING,
                    detail = preloadSignalDetail(
                        result = result,
                        signal = EarlyMountPreloadSignal.PEER_GROUP_GAP,
                    ),
                    detailMonospace = true,
                ),
            )
        }
    }
}

internal fun mergePreloadFindings(
    baseFindings: List<MountFinding>,
    preloadFindings: List<MountFinding>,
): List<MountFinding> {
    if (preloadFindings.isEmpty()) {
        return collapseMountIdFindings(baseFindings)
    }

    val merged = baseFindings.toMutableList()
    val preloadMountId =
        preloadFindings.firstOrNull { it.id == "early_preload_mount_id_loophole" }
    val runtimeMountIdFindings = merged.filter { it.label == "Mount ID loophole" }

    if (preloadMountId != null || runtimeMountIdFindings.size > 1) {
        merged.removeAll(runtimeMountIdFindings.toSet())
        mergeMountIdFinding(runtimeMountIdFindings, preloadMountId)?.let(merged::add)
    }

    preloadFindings
        .filterNot { it.id == "early_preload_mount_id_loophole" }
        .forEach(merged::add)

    return merged
}

private fun collapseMountIdFindings(findings: List<MountFinding>): List<MountFinding> {
    val mountIdFindings = findings.filter { it.label == "Mount ID loophole" }
    if (mountIdFindings.size <= 1) {
        return findings
    }

    val merged = findings.toMutableList()
    merged.removeAll(mountIdFindings.toSet())
    mergeMountIdFinding(
        runtimeFindings = mountIdFindings,
        preloadFinding = null
    )?.let(merged::add)
    return merged
}

private fun mergeMountIdFinding(
    runtimeFindings: List<MountFinding>,
    preloadFinding: MountFinding?,
): MountFinding? {
    if (runtimeFindings.isEmpty() && preloadFinding == null) {
        return null
    }

    if (runtimeFindings.size == 1 && preloadFinding == null) {
        return runtimeFindings.first()
    }

    val detailParts = buildList {
        if (preloadFinding != null) {
            add("Startup preload: ${preloadFinding.detail ?: preloadFinding.value}")
        }
        runtimeFindings.forEach { finding ->
            add("Runtime mountinfo: ${finding.detail ?: finding.value}")
        }
    }

    return MountFinding(
        id = if (runtimeFindings.isNotEmpty()) {
            "mount_id_loophole"
        } else {
            "early_preload_mount_id_loophole"
        },
        label = "Mount ID loophole",
        value = when {
            runtimeFindings.isNotEmpty() && preloadFinding != null -> "Startup + runtime"
            runtimeFindings.size > 1 -> "Multiple gaps"
            preloadFinding != null -> preloadFinding.value
            else -> runtimeFindings.firstOrNull()?.value ?: "Detected"
        },
        group = MountFindingGroup.CONSISTENCY,
        severity = MountFindingSeverity.DANGER,
        detail = detailParts.joinToString(separator = ". ", postfix = "."),
        detailMonospace = runtimeFindings.any { it.detailMonospace } || preloadFinding?.detailMonospace == true,
    )
}

private fun preloadSignalDetail(
    result: EarlyMountPreloadResult,
    signal: EarlyMountPreloadSignal,
    extras: List<String> = emptyList(),
): String {
    val parts = mutableListOf("Source=startup preload")
    if (!result.isContextValid) {
        parts += "context=stale"
    }
    parts += result.messagesFor(signal)
    parts += extras.filter { it.isNotBlank() }
    if (parts.size == 1 && result.details.isNotBlank()) {
        parts += result.details
    }
    return parts.joinToString(separator = " | ")
}

private const val SMALL_DATA_MIRROR_GAP_THRESHOLD = 2
private val SMALL_DATA_MIRROR_SINGLE_MOUNT_ID_REGEX =
    Regex("""Missing mount ID \d+ before /data_mirror(?:\b.*)?""")
private val SMALL_DATA_MIRROR_MULTI_MOUNT_ID_REGEX =
    Regex("""Missing (\d+) mount IDs before /data_mirror(?:\b.*)?""")
