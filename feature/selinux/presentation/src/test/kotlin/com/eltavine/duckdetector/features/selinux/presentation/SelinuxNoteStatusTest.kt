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

package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditIntegrityAnalysis
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditIntegrityState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditNote
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditNoteKind
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyAnalysis
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyNote
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyNoteKind
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyWeakness
import org.junit.Assert.assertEquals
import org.junit.Test

class SelinuxNoteStatusTest {

    @Test
    fun `each policy note kind keeps the status its text used to get`() {
        val expected = mapOf(
            SelinuxPolicyNoteKind.VERSION_MEETS_MINIMUM to DetectorStatus.allClear(),
            SelinuxPolicyNoteKind.VERSION_BELOW_MINIMUM to DetectorStatus.warning(),
            SelinuxPolicyNoteKind.VERSION_UNREADABLE to DetectorStatus.info(InfoKind.SUPPORT),
            SelinuxPolicyNoteKind.CLASSES_COMPLETE to DetectorStatus.info(InfoKind.SUPPORT),
            SelinuxPolicyNoteKind.CLASSES_MISSING to DetectorStatus.warning(),
            SelinuxPolicyNoteKind.CLASSES_UNREADABLE to DetectorStatus.info(InfoKind.SUPPORT),
            SelinuxPolicyNoteKind.DANGEROUS_CONTEXT_TYPES to DetectorStatus.danger(),
            SelinuxPolicyNoteKind.CONTEXT_TYPE_NORMAL to DetectorStatus.allClear(),
            SelinuxPolicyNoteKind.PERMISSIVE_DOMAINS_FOUND to DetectorStatus.warning(),
            SelinuxPolicyNoteKind.NO_PERMISSIVE_DOMAINS to DetectorStatus.warning(),
        )
        val notes = buildPolicyNotes(analysis(SelinuxPolicyNoteKind.entries.map { SelinuxPolicyNote(it, it.name) }))

        assertEquals(SelinuxPolicyNoteKind.entries.map { expected.getValue(it) }, notes.map { it.status })
        assertEquals(SelinuxPolicyNoteKind.entries.map { it.name }, notes.map { it.text })
    }

    @Test
    fun `each audit note kind keeps the status its text used to get`() {
        val expected = mapOf(
            SelinuxAuditNoteKind.PROBES_EXPOSED_TAMPERING to DetectorStatus.info(InfoKind.SUPPORT),
            SelinuxAuditNoteKind.SIDE_CHANNEL_LEAK to DetectorStatus.warning(),
            SelinuxAuditNoteKind.DIRECT_PROBE_NOT_LEAKED to DetectorStatus.allClear(),
            SelinuxAuditNoteKind.EVENT_BUFFER_CLEAN to DetectorStatus.info(InfoKind.SUPPORT),
            SelinuxAuditNoteKind.EVENTS_NOT_GUARANTEED to DetectorStatus.info(InfoKind.SUPPORT),
            SelinuxAuditNoteKind.EVENT_LOGS_UNAVAILABLE to DetectorStatus.info(InfoKind.SUPPORT),
            SelinuxAuditNoteKind.SU_ACTOR_REFERENCED to DetectorStatus.warning(),
            SelinuxAuditNoteKind.RESIDUE_FOUND to DetectorStatus.warning(),
            SelinuxAuditNoteKind.NO_RESIDUE to DetectorStatus.info(InfoKind.SUPPORT),
            SelinuxAuditNoteKind.RESIDUE_UNCHECKED to DetectorStatus.info(InfoKind.SUPPORT),
            SelinuxAuditNoteKind.ABSENCE_NOT_PROOF to DetectorStatus.info(InfoKind.SUPPORT),
        )
        val notes = buildAuditNotes(
            SelinuxAuditIntegrityAnalysis(
                state = SelinuxAuditIntegrityState.INCONCLUSIVE,
                residueHits = emptyList(),
                runtimeHits = emptyList(),
                sideChannelHits = emptyList(),
                logcatChecked = true,
                notes = SelinuxAuditNoteKind.entries.map { SelinuxAuditNote(it, it.name) },
            ),
        )

        assertEquals(SelinuxAuditNoteKind.entries.map { expected.getValue(it) }, notes.map { it.status })
    }

    private fun analysis(notes: List<SelinuxPolicyNote>) = SelinuxPolicyAnalysis(
        policyVersion = 33,
        policyVersionOk = true,
        classCount = 0,
        classCountOk = false,
        foundClasses = emptyList(),
        missingClasses = emptyList(),
        dangerousTypesFound = emptyList(),
        permissiveDomains = emptyList(),
        processContext = null,
        contextType = null,
        weakness = SelinuxPolicyWeakness.NONE,
        notes = notes,
    )
}
