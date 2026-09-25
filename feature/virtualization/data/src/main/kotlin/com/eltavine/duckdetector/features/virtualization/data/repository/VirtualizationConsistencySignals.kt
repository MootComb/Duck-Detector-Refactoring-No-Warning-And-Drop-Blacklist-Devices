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

package com.eltavine.duckdetector.features.virtualization.data.repository

import com.eltavine.duckdetector.capability.earlypreload.data.EarlyVirtualizationPreloadResult
import com.eltavine.duckdetector.capability.helperprocess.data.HelperProcessProfile
import com.eltavine.duckdetector.capability.helperprocess.data.HelperProcessSnapshot
import com.eltavine.duckdetector.capability.helperprocess.data.VirtualizationNativeFinding
import com.eltavine.duckdetector.capability.helperprocess.data.VirtualizationNativeSnapshot
import com.eltavine.duckdetector.features.virtualization.data.probes.DexPathProbeResult
import com.eltavine.duckdetector.features.virtualization.data.probes.UidIdentityProbeResult
import com.eltavine.duckdetector.features.virtualization.data.rules.VirtualizationHostAppsCatalog
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignal
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalGroup
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity

internal fun buildConsistencySignals(
    nativeSnapshot: VirtualizationNativeSnapshot,
    preloadResult: EarlyVirtualizationPreloadResult,
    remoteSnapshot: HelperProcessSnapshot,
    isolatedSnapshot: HelperProcessSnapshot,
    mainProcessInfo: VirtualizationProcessInfo,
    dexPathResult: DexPathProbeResult,
    uidIdentityResult: UidIdentityProbeResult,
): ConsistencyComputation {
    val crossSignals = mutableListOf<VirtualizationSignal>()
    val isolatedSignals = mutableListOf<VirtualizationSignal>()
    var mountAnchorDriftCount = 0

    if (remoteSnapshot.available && remoteSnapshot.profile == HelperProcessProfile.REGULAR) {
        val pathMismatches = buildList {
            if (
                mainProcessInfo.filesDir.isNotBlank() &&
                remoteSnapshot.filesDir.isNotBlank() &&
                mainProcessInfo.filesDir != remoteSnapshot.filesDir
            ) add("filesDir main=${mainProcessInfo.filesDir} helper=${remoteSnapshot.filesDir}")
            if (
                mainProcessInfo.cacheDir.isNotBlank() &&
                remoteSnapshot.cacheDir.isNotBlank() &&
                mainProcessInfo.cacheDir != remoteSnapshot.cacheDir
            ) add("cacheDir main=${mainProcessInfo.cacheDir} helper=${remoteSnapshot.cacheDir}")
            if (
                mainProcessInfo.codePath.isNotBlank() &&
                remoteSnapshot.codePath.isNotBlank() &&
                mainProcessInfo.codePath != remoteSnapshot.codePath
            ) add("codePath main=${mainProcessInfo.codePath} helper=${remoteSnapshot.codePath}")
        }
        if (pathMismatches.isNotEmpty()) {
            crossSignals += VirtualizationSignal(
                id = "virt_consistency_paths",
                label = "Cross-process path drift",
                value = "Review",
                group = VirtualizationSignalGroup.CONSISTENCY,
                severity = VirtualizationSignalSeverity.WARNING,
                detail = pathMismatches.joinToString(separator = "\n"),
                detailMonospace = true,
            )
        }

        val mainComparableArtifacts = comparableArtifactKeys(nativeSnapshot.findings)
        val helperComparableArtifacts = comparableArtifactKeys(remoteSnapshot.findings)
        val onlyInMain = (mainComparableArtifacts - helperComparableArtifacts).take(6)
        val onlyInHelper = (helperComparableArtifacts - mainComparableArtifacts).take(6)
        if (onlyInMain.isNotEmpty() || onlyInHelper.isNotEmpty()) {
            crossSignals += VirtualizationSignal(
                id = "virt_consistency_artifacts",
                label = "Cross-process artifact drift",
                value = "Review",
                group = VirtualizationSignalGroup.CONSISTENCY,
                severity = VirtualizationSignalSeverity.WARNING,
                detail = buildString {
                    if (onlyInMain.isNotEmpty()) {
                        append("Only in main:\n")
                        append(onlyInMain.joinToString(separator = "\n"))
                    }
                    if (onlyInHelper.isNotEmpty()) {
                        if (isNotEmpty()) append("\n\n")
                        append("Only in helper:\n")
                        append(onlyInHelper.joinToString(separator = "\n"))
                    }
                },
                detailMonospace = true,
            )
        }
    }

    if (
        preloadResult.hasDangerSignal &&
        nativeSnapshot.findings.none { it.severity.equals("DANGER", ignoreCase = true) }
    ) {
        crossSignals += VirtualizationSignal(
            id = "virt_consistency_preload_drift",
            label = "Startup/runtime drift",
            value = "Review",
            group = VirtualizationSignalGroup.CONSISTENCY,
            severity = VirtualizationSignalSeverity.WARNING,
            detail = "Startup preload saw virtualization artifacts that were not visible from the later runtime snapshot.",
        )
    }

    val mainHasHostResidue = dexPathResult.hostPathHit || uidIdentityResult.hostPackageHit
    val helperHasHostResidue =
        remoteSnapshot.classPathEntries.any(VirtualizationHostAppsCatalog::containsHostToken) ||
                remoteSnapshot.packagesForUid.any {
                    VirtualizationHostAppsCatalog.targetByPackage.containsKey(it)
                }
    val isolatedHasHostResidue =
        isolatedSnapshot.classPathEntries.any(VirtualizationHostAppsCatalog::containsHostToken) ||
                isolatedSnapshot.packagesForUid.any {
                    VirtualizationHostAppsCatalog.targetByPackage.containsKey(it)
                }

    if ((mainHasHostResidue || helperHasHostResidue) && isolatedSnapshot.available && !isolatedHasHostResidue) {
        isolatedSignals += VirtualizationSignal(
            id = "virt_isolated_host_residue",
            label = "Isolated process stayed clean",
            value = "Danger",
            group = VirtualizationSignalGroup.CONSISTENCY,
            severity = VirtualizationSignalSeverity.DANGER,
            detail = buildString {
                append("Main/helper showed host classpath or UID residue while isolated process did not.\n")
                append("mainHost=")
                append(mainHasHostResidue)
                append(" helperHost=")
                append(helperHasHostResidue)
                append(" isolatedHost=")
                append(isolatedHasHostResidue)
            },
            detailMonospace = true,
        )
    }

    if (remoteSnapshot.available) {
        val regularAnchorResult = compareMountAnchors(
            prefix = "Cross-process",
            mainNamespace = nativeSnapshot.mountNamespaceInode,
            mainApex = nativeSnapshot.apexMountKey,
            mainSystem = nativeSnapshot.systemMountKey,
            mainVendor = nativeSnapshot.vendorMountKey,
            otherNamespace = remoteSnapshot.mountNamespaceInode,
            otherApex = remoteSnapshot.apexMountKey,
            otherSystem = remoteSnapshot.systemMountKey,
            otherVendor = remoteSnapshot.vendorMountKey,
            severity = VirtualizationSignalSeverity.DANGER,
        )
        crossSignals += regularAnchorResult.crossProcessSignals
        mountAnchorDriftCount += regularAnchorResult.mountAnchorDriftCount
    }

    if (isolatedSnapshot.available) {
        val isolatedAnchorResult = compareMountAnchors(
            prefix = "Isolated",
            mainNamespace = nativeSnapshot.mountNamespaceInode,
            mainApex = nativeSnapshot.apexMountKey,
            mainSystem = nativeSnapshot.systemMountKey,
            mainVendor = nativeSnapshot.vendorMountKey,
            otherNamespace = isolatedSnapshot.mountNamespaceInode,
            otherApex = isolatedSnapshot.apexMountKey,
            otherSystem = isolatedSnapshot.systemMountKey,
            otherVendor = isolatedSnapshot.vendorMountKey,
            severity = VirtualizationSignalSeverity.DANGER,
        )
        isolatedSignals += isolatedAnchorResult.crossProcessSignals
        mountAnchorDriftCount += isolatedAnchorResult.mountAnchorDriftCount
    }

    if (preloadResult.hasRun) {
        val preloadAnchorResult = compareMountAnchors(
            prefix = "Startup/runtime",
            mainNamespace = preloadResult.mountNamespaceInode,
            mainApex = preloadResult.apexMountKey,
            mainSystem = preloadResult.systemMountKey,
            mainVendor = preloadResult.vendorMountKey,
            otherNamespace = nativeSnapshot.mountNamespaceInode,
            otherApex = nativeSnapshot.apexMountKey,
            otherSystem = nativeSnapshot.systemMountKey,
            otherVendor = nativeSnapshot.vendorMountKey,
            severity = VirtualizationSignalSeverity.WARNING,
        )
        crossSignals += preloadAnchorResult.crossProcessSignals
        mountAnchorDriftCount += preloadAnchorResult.mountAnchorDriftCount
    }

    return ConsistencyComputation(
        crossProcessSignals = crossSignals.distinctBy { it.id },
        isolatedSignals = isolatedSignals.distinctBy { it.id },
        mountAnchorDriftCount = mountAnchorDriftCount,
    )
}

private fun compareMountAnchors(
    prefix: String,
    mainNamespace: String,
    mainApex: String,
    mainSystem: String,
    mainVendor: String,
    otherNamespace: String,
    otherApex: String,
    otherSystem: String,
    otherVendor: String,
    severity: VirtualizationSignalSeverity,
): ConsistencyComputation {
    if (
        mainNamespace.isBlank() &&
        mainApex.isBlank() &&
        mainSystem.isBlank() &&
        mainVendor.isBlank()
    ) {
        return ConsistencyComputation()
    }

    val driftLines = buildList {
        compareSingleMountAnchor("/apex", mainApex, otherApex)?.let(::add)
        compareSingleMountAnchor("/system", mainSystem, otherSystem)?.let(::add)
        compareSingleMountAnchor("/vendor", mainVendor, otherVendor)?.let(::add)
    }
    val comparableAnchorCount = listOf(
        mainApex to otherApex,
        mainSystem to otherSystem,
        mainVendor to otherVendor,
    ).count { (mainRaw, otherRaw) -> hasComparableMountAnchors(mainRaw, otherRaw) }
    val namespaceDrift = mainNamespace.isNotBlank() &&
            otherNamespace.isNotBlank() &&
            mainNamespace != otherNamespace
    val signals = mutableListOf<VirtualizationSignal>()

    if (driftLines.isNotEmpty()) {
        signals += VirtualizationSignal(
            id = "virt_mount_drift_${prefix.lowercase().replace(" ", "_")}",
            label = "$prefix mount anchor drift",
            value = "Danger",
            group = VirtualizationSignalGroup.CONSISTENCY,
            severity = severity,
            detail = driftLines.joinToString(separator = "\n"),
            detailMonospace = true,
        )
    } else if (namespaceDrift && comparableAnchorCount == 0) {
        signals += VirtualizationSignal(
            id = "virt_namespace_drift_${prefix.lowercase().replace(" ", "_")}",
            label = "$prefix namespace drift",
            value = "Review",
            group = VirtualizationSignalGroup.CONSISTENCY,
            severity = VirtualizationSignalSeverity.WARNING,
            detail = "mnt namespace main=$mainNamespace other=$otherNamespace",
            detailMonospace = true,
        )
    }

    return ConsistencyComputation(
        crossProcessSignals = signals,
        mountAnchorDriftCount = driftLines.size,
    )
}

private fun compareSingleMountAnchor(
    label: String,
    mainRaw: String,
    otherRaw: String,
): String? {
    if (mainRaw.isBlank() && otherRaw.isBlank()) {
        return null
    }
    if (mainRaw.isBlank() || otherRaw.isBlank()) {
        return "$label main=${mainRaw.ifBlank { "<missing>" }} other=${otherRaw.ifBlank { "<missing>" }}"
    }

    val mainAnchor = ParsedMountAnchor.parse(mainRaw) ?: return null
    val otherAnchor = ParsedMountAnchor.parse(otherRaw) ?: return null
    if (mainAnchor.semanticKey == otherAnchor.semanticKey) {
        return null
    }
    return "$label main=${mainAnchor.semanticSummary()} other=${otherAnchor.semanticSummary()}"
}

private fun hasComparableMountAnchors(
    mainRaw: String,
    otherRaw: String,
): Boolean {
    return ParsedMountAnchor.parse(mainRaw) != null && ParsedMountAnchor.parse(otherRaw) != null
}

private fun comparableArtifactKeys(
    findings: List<VirtualizationNativeFinding>,
): Set<String> {
    return findings.asSequence()
        .filterNot { it.severity.equals("INFO", ignoreCase = true) }
        .filterNot { it.label.equals("Graphics renderer", ignoreCase = true) }
        .map { "${it.group}:${it.label}:${it.value}" }
        .toCollection(linkedSetOf())
}

private data class ParsedMountAnchor(
    val mountId: String,
    val majorMinor: String,
    val root: String,
    val mountPoint: String,
    val fsType: String,
    val source: String,
) {
    val semanticKey: String
        get() = listOf(
            normalizeMountField(majorMinor),
            normalizeMountPath(root),
            normalizeMountPath(mountPoint),
            normalizeMountField(fsType),
            normalizeMountPath(source),
        ).joinToString("|")

    fun semanticSummary(): String {
        return "dev=$majorMinor root=$root point=$mountPoint fs=$fsType source=$source"
    }

    companion object {
        fun parse(raw: String): ParsedMountAnchor? {
            if (raw.isBlank()) {
                return null
            }
            val parts = raw.split('|', limit = 6)
            if (parts.size != 6) {
                return null
            }
            return ParsedMountAnchor(
                mountId = parts[0].trim(),
                majorMinor = parts[1].trim(),
                root = parts[2].trim(),
                mountPoint = parts[3].trim(),
                fsType = parts[4].trim(),
                source = parts[5].trim(),
            )
        }

        private fun normalizeMountField(value: String): String {
            return value.trim().lowercase()
        }

        private fun normalizeMountPath(value: String): String {
            val normalized = value.trim()
                .replace('\\', '/')
                .replace(Regex("/+"), "/")
            return if (normalized.length > 1 && normalized.endsWith('/')) {
                normalized.dropLast(1).lowercase()
            } else {
                normalized.lowercase()
            }
        }
    }
}
