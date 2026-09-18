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

package com.eltavine.duckdetector.features.mount.domain

enum class MountStage {
    LOADING,
    READY,
    FAILED,
}

enum class MountFindingGroup {
    ARTIFACTS,
    RUNTIME,
    FILESYSTEM,
    CONSISTENCY,
}

enum class MountFindingSeverity {
    SAFE,
    WARNING,
    DANGER,
    INFO,
}

enum class MountMethodOutcome {
    CLEAN,
    WARNING,
    DANGER,
    SUPPORT,
}

data class MountFinding(
    val id: String,
    val label: String,
    val value: String,
    val group: MountFindingGroup,
    val severity: MountFindingSeverity,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class MountImpact(
    val text: String,
    val severity: MountFindingSeverity,
)

data class MountMethodResult(
    val label: String,
    val summary: String,
    val outcome: MountMethodOutcome,
    val detail: String? = null,
)

enum class MountZygoteNextState {
    PENDING,
    UNSUPPORTED,
    UNAVAILABLE,
    READY,
}

enum class MountZygoteNextNamespaceAssessment {
    LIKELY_INIT,
    PRIVATE_ANOMALY,
    INCONSISTENT,
    UNVERIFIED,
}

enum class MountZygoteNextExposure {
    NONE,
    ROOT_MOUNT_EXPOSURE,
}

data class MountZygoteNextMarker(
    val labels: List<String>,
    val mountPoint: String,
    val mountRoot: String,
    val fileSystemType: String,
    val source: String,
    val rawLine: String,
) {
    val dangerous: Boolean
        get() = labels.any { it != DEBUG_RAMDISK_LABEL }

    companion object {
        private const val DEBUG_RAMDISK_LABEL = "debug_ramdisk"
    }
}

data class MountZygoteNextReport(
    val state: MountZygoteNextState,
    val sdkInt: Int,
    val mainNamespaceInode: Long = 0L,
    val mainUid: Int = 0,
    val mainPropagation: String = "",
    val mainRootMountId: Long = 0L,
    val mainMinimumMountId: Long = 0L,
    val mainMaximumMountId: Long = 0L,
    val mainMountCount: Int = 0,
    val mainMountIdsByPoint: Map<String, Long> = emptyMap(),
    val mainMarkers: List<MountZygoteNextMarker> = emptyList(),
    val isolatedNamespaceInode: Long = 0L,
    val isolatedParentPid: Int = 0,
    val isolatedUid: Int = 0,
    val isolatedPropagation: String = "",
    val isolatedRootMountId: Long = 0L,
    val isolatedMinimumMountId: Long = 0L,
    val isolatedMaximumMountId: Long = 0L,
    val isolatedMountCount: Int = 0,
    val isolatedMountIdsByPoint: Map<String, Long> = emptyMap(),
    val isolatedMarkers: List<MountZygoteNextMarker> = emptyList(),
    val errorDetail: String = "",
) {
    val dangerousMarkers: List<MountZygoteNextMarker>
        get() = isolatedMarkers.filter(MountZygoteNextMarker::dangerous)

    val leakDetected: Boolean
        get() = state == MountZygoteNextState.READY && dangerousMarkers.isNotEmpty()

    val exposure: MountZygoteNextExposure
        get() = if (leakDetected) {
            MountZygoteNextExposure.ROOT_MOUNT_EXPOSURE
        } else {
            MountZygoteNextExposure.NONE
        }

    /**
     * AOSP init makes the root mount shared before creating its bootstrap/default namespaces.
     * Classic zygote clones that view and recursively changes its root to slave, while zygote_next
     * and its native descendants only fork and retain init's default namespace. The kernel assigns
     * fresh mount IDs while cloning a namespace. The init-derived view should therefore retain a
     * lower root/minimum ID and lower IDs at several stable mountpoint anchors than a later
     * classic-app clone. Its maximum ID is not used: init can receive new mounts long after boot.
     * IDs can be reused, so this is corroborating evidence rather than proof by itself.
     */
    val namespaceAssessment: MountZygoteNextNamespaceAssessment
        get() {
            if (state != MountZygoteNextState.READY) {
                return MountZygoteNextNamespaceAssessment.UNVERIFIED
            }
            if (!isolatedRouteValidated) {
                return MountZygoteNextNamespaceAssessment.UNVERIFIED
            }
            if (!mountEvidenceAvailable) {
                return MountZygoteNextNamespaceAssessment.UNVERIFIED
            }
            if (propagationContradictsInitSignature || anchorChronologyContradicted) {
                return MountZygoteNextNamespaceAssessment.INCONSISTENT
            }
            if (isolatedRootIsPrivate) {
                return MountZygoteNextNamespaceAssessment.PRIVATE_ANOMALY
            }
            if (namespaceSeparated && propagationMatchesAosp && mountIdOrderingMatchesAosp) {
                return MountZygoteNextNamespaceAssessment.LIKELY_INIT
            }
            return MountZygoteNextNamespaceAssessment.UNVERIFIED
        }

    val hasInitNamespaceCoverage: Boolean
        get() = namespaceAssessment == MountZygoteNextNamespaceAssessment.LIKELY_INIT

    val isolatedRouteValidated: Boolean
        get() = isolatedUid.isIsolatedUid()

    val namespaceAssessmentDetail: String
        get() {
            when (namespaceAssessment) {
                MountZygoteNextNamespaceAssessment.LIKELY_INIT -> return "The native view matches AOSP's init-managed default namespace: " +
                    "it is distinct from the classic app namespace, its root is shared and " +
                    "non-slave, the classic root is slave, and at least two thirds of three or " +
                    "more common anchor IDs plus its root/minimum IDs are older. This is a " +
                    "likely signature, not proof of namespace lineage."

                MountZygoteNextNamespaceAssessment.PRIVATE_ANOMALY -> return "The native isolated route is valid, but its root is private/slave instead of the stock shared init-managed view."

                MountZygoteNextNamespaceAssessment.INCONSISTENT -> return "Propagation fields or mount-ID anchor chronology contradict the init-managed signature."

                MountZygoteNextNamespaceAssessment.UNVERIFIED -> Unit
            }
            if (!isolatedRouteValidated) {
                return "The native isolated route or isolated UID could not be validated."
            }
            val reasons = buildList {
                if (!namespaceSeparated) add("namespace identities are missing or equal")
                if (!isolatedRootIsSharedNonSlave) {
                    add("native root is not shared and non-slave")
                }
                if (!mainRootIsSlaveNonShared) {
                    add("classic app root is not slave and non-shared")
                }
                if (!mountRecordCountsSufficient) {
                    add("mountinfo record count is too small for a namespace comparison")
                }
                if (anchorPairs.size < MIN_ANCHOR_PAIRS) {
                    add("fewer than $MIN_ANCHOR_PAIRS common anchor mount IDs")
                } else if (!anchorChronologySupported) {
                    add("native root/minimum/anchor mount IDs are not older than the classic app IDs")
                }
            }
            return "Init-managed namespace coverage is unverified" +
                if (reasons.isEmpty()) "." else ": ${reasons.joinToString()}."
        }

    val contrastObserved: Boolean
        get() = hasInitNamespaceCoverage

    private val namespaceSeparated: Boolean
        get() = mainNamespaceInode > 0L && isolatedNamespaceInode > 0L &&
            mainNamespaceInode != isolatedNamespaceInode

    private val propagationMatchesAosp: Boolean
        get() = isolatedRootIsSharedNonSlave && mainRootIsSlaveNonShared

    private val mountEvidenceAvailable: Boolean
        get() = mainRootMountId > 0L && isolatedRootMountId > 0L &&
            mainMinimumMountId > 0L && isolatedMinimumMountId > 0L &&
            mountRecordCountsSufficient

    private val mountRecordCountsSufficient: Boolean
        get() = mainMountCount >= MIN_MOUNT_RECORDS &&
            isolatedMountCount >= MIN_MOUNT_RECORDS

    private val propagationContradictsInitSignature: Boolean
        get() = propagationFields(mainPropagation).hasSharedAndMaster() ||
            propagationFields(isolatedPropagation).hasSharedAndMaster()

    private val isolatedRootIsSharedNonSlave: Boolean
        get() {
            val fields = propagationFields(isolatedPropagation)
            return fields.any { it.startsWith("shared:") } &&
                fields.none { it.startsWith("master:") }
        }

    private val mainRootIsSlaveNonShared: Boolean
        get() {
            val fields = propagationFields(mainPropagation)
            return fields.any { it.startsWith("master:") } &&
                fields.none { it.startsWith("shared:") }
        }

    private val mountIdOrderingMatchesAosp: Boolean
        get() = isolatedRootMountId > 0L && mainRootMountId > isolatedRootMountId &&
            isolatedMinimumMountId > 0L && mainMinimumMountId > isolatedMinimumMountId &&
            anchorChronologySupported

    private val anchorPairs: Set<String>
        get() = mainMountIdsByPoint.keys.intersect(isolatedMountIdsByPoint.keys)

    private val olderAnchorCount: Int
        get() = anchorPairs.count { point ->
            isolatedMountIdsByPoint.getValue(point) < mainMountIdsByPoint.getValue(point)
        }

    private val anchorChronologySupported: Boolean
        get() = anchorPairs.size >= MIN_ANCHOR_PAIRS && olderAnchorCount * 3 >= anchorPairs.size * 2

    private val anchorChronologyContradicted: Boolean
        get() = anchorPairs.size >= MIN_ANCHOR_PAIRS && olderAnchorCount * 3 < anchorPairs.size

    private val isolatedRootIsPrivate: Boolean
        get() = isolatedRootMountId > 0L &&
            propagationFields(isolatedPropagation).none { it.startsWith("shared:") }

    private fun Int.isIsolatedUid(): Boolean {
        val appId = this % 100_000
        return appId in 90_000..99_999
    }

    private fun propagationFields(value: String): List<String> {
        return value.split(' ').filter(String::isNotBlank)
    }

    private fun List<String>.hasSharedAndMaster(): Boolean {
        return any { it.startsWith("shared:") } && any { it.startsWith("master:") }
    }

    companion object {
        private const val MIN_ANCHOR_PAIRS = 3
        private const val MIN_MOUNT_RECORDS = 8

        fun pending(): MountZygoteNextReport {
            return MountZygoteNextReport(
                state = MountZygoteNextState.PENDING,
                sdkInt = 0,
            )
        }
    }
}

data class MountReport(
    val stage: MountStage,
    val nativeAvailable: Boolean,
    val mountsReadable: Boolean,
    val mountInfoReadable: Boolean,
    val mapsReadable: Boolean,
    val filesystemsReadable: Boolean,
    val initNamespaceReadable: Boolean,
    val statxSupported: Boolean,
    val permissionTotal: Int,
    val permissionDenied: Int,
    val permissionAccessible: Int,
    val mountEntryCount: Int,
    val mountInfoEntryCount: Int,
    val mapLineCount: Int,
    val earlyPreloadAvailable: Boolean,
    val earlyPreloadDetected: Boolean,
    val earlyPreloadContextValid: Boolean,
    val earlyPreloadFindingCount: Int,
    val findings: List<MountFinding>,
    val impacts: List<MountImpact>,
    val methods: List<MountMethodResult>,
    val errorMessage: String? = null,
    val zygoteNext: MountZygoteNextReport = MountZygoteNextReport.pending(),
    val procMountViewProbeAvailable: Boolean = false,
    val procMountViewDistinctCount: Int = 0,
    val procMountViewExpectedCount: Int = 1,
    val procMountViewPidCount: Int = 0,
    val procMountViewDivergent: Boolean = false,
    val procMountViewTokenHit: Boolean = false,
    val procMountViewTokenKind: String = "",
    val procMountViewTokenDetail: String = "",
    val procMountViewDetail: String = "",
) {
    val artifactRows: List<MountFinding>
        get() = findings.filter { it.group == MountFindingGroup.ARTIFACTS }

    val runtimeRows: List<MountFinding>
        get() = findings.filter { it.group == MountFindingGroup.RUNTIME }

    val filesystemRows: List<MountFinding>
        get() = findings.filter { it.group == MountFindingGroup.FILESYSTEM }

    val consistencyRows: List<MountFinding>
        get() = findings.filter { it.group == MountFindingGroup.CONSISTENCY }

    val dangerFindings: List<MountFinding>
        get() = findings.filter { it.severity == MountFindingSeverity.DANGER }

    val warningFindings: List<MountFinding>
        get() = findings.filter { it.severity == MountFindingSeverity.WARNING }

    val dangerSignalCount: Int
        get() = dangerFindings.size +
                (if (procMountViewTokenHit) 1 else 0) +
                (if (zygoteNext.exposure == MountZygoteNextExposure.ROOT_MOUNT_EXPOSURE &&
                    dangerFindings.none { it.id == "zygote_next_root_mount_exposure" }
                ) 1 else 0)

    val warningSignalCount: Int
        get() = warningFindings.size + if (procMountViewDivergent && !procMountViewTokenHit) 1 else 0

    companion object {
        fun loading(): MountReport {
            return MountReport(
                stage = MountStage.LOADING,
                nativeAvailable = true,
                mountsReadable = false,
                mountInfoReadable = false,
                mapsReadable = false,
                filesystemsReadable = false,
                initNamespaceReadable = false,
                statxSupported = false,
                permissionTotal = 0,
                permissionDenied = 0,
                permissionAccessible = 0,
                mountEntryCount = 0,
                mountInfoEntryCount = 0,
                mapLineCount = 0,
                earlyPreloadAvailable = false,
                earlyPreloadDetected = false,
                earlyPreloadContextValid = false,
                earlyPreloadFindingCount = 0,
                findings = emptyList(),
                impacts = emptyList(),
                methods = emptyList(),
            )
        }

        fun failed(message: String): MountReport {
            return MountReport(
                stage = MountStage.FAILED,
                nativeAvailable = false,
                mountsReadable = false,
                mountInfoReadable = false,
                mapsReadable = false,
                filesystemsReadable = false,
                initNamespaceReadable = false,
                statxSupported = false,
                permissionTotal = 0,
                permissionDenied = 0,
                permissionAccessible = 0,
                mountEntryCount = 0,
                mountInfoEntryCount = 0,
                mapLineCount = 0,
                earlyPreloadAvailable = false,
                earlyPreloadDetected = false,
                earlyPreloadContextValid = false,
                earlyPreloadFindingCount = 0,
                findings = emptyList(),
                impacts = emptyList(),
                methods = emptyList(),
                errorMessage = message,
            )
        }
    }
}
