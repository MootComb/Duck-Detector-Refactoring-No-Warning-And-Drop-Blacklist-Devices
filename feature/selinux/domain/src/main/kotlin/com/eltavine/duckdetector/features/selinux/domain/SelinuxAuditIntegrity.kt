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

package com.eltavine.duckdetector.features.selinux.domain

enum class SelinuxAuditIntegrityState {
    CLEAR,
    RESIDUE,
    EXPOSED,
    TAMPERED,
    INCONCLUSIVE,
}

data class SelinuxAuditEvidence(
    val label: String,
    val value: String,
    val detail: String? = null,
    val strongSignal: Boolean = false,
)

/** What an audit integrity note says. */
enum class SelinuxAuditNoteKind {
    PROBES_EXPOSED_TAMPERING,
    SIDE_CHANNEL_LEAK,
    DIRECT_PROBE_NOT_LEAKED,
    EVENT_BUFFER_CLEAN,
    EVENTS_NOT_GUARANTEED,
    EVENT_LOGS_UNAVAILABLE,
    SU_ACTOR_REFERENCED,
    RESIDUE_FOUND,
    NO_RESIDUE,
    RESIDUE_UNCHECKED,
    ABSENCE_NOT_PROOF,
}

data class SelinuxAuditNote(
    val kind: SelinuxAuditNoteKind,
    val text: String,
)

data class SelinuxAuditIntegrityAnalysis(
    val state: SelinuxAuditIntegrityState,
    val residueHits: List<SelinuxAuditEvidence>,
    /** False when a residue location could not be stat-ed, so finding none does not show absence. */
    val residueObservable: Boolean = true,
    val runtimeHits: List<SelinuxAuditEvidence>,
    val sideChannelHits: List<SelinuxAuditEvidence>,
    val suspiciousActorHits: List<SelinuxAuditEvidence> = emptyList(),
    val logcatChecked: Boolean,
    val directProbeUsed: Boolean = false,
    val notes: List<SelinuxAuditNote>,
)
