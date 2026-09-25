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

import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.presentation.model.SelinuxCardModel

class SelinuxCardModelMapper {

    fun map(report: SelinuxReport): SelinuxCardModel {
        return SelinuxCardModel(
            title = "SELinux",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            stateRows = buildStateRows(report),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            policyRows = buildPolicyRows(report.policyAnalysis),
            policyNotes = buildPolicyNotes(report.policyAnalysis),
            auditRows = buildAuditRows(report.auditIntegrity),
            auditNotes = buildAuditNotes(report.auditIntegrity),
            deviceRows = buildDeviceRows(report),
            references = buildReferences(),
        )
    }
}
