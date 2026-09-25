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

package com.eltavine.duckdetector.features.lsposed.presentation

import com.eltavine.duckdetector.features.lsposed.domain.LSPosedReport
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.toDetectorStatus
import com.eltavine.duckdetector.features.lsposed.presentation.model.LSPosedCardModel

class LSPosedCardModelMapper {

    fun map(report: LSPosedReport): LSPosedCardModel {
        return LSPosedCardModel(
            title = "LSPosed",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            runtimeRows = buildRowsForGroup(report, LSPosedSignalGroup.RUNTIME, "Runtime probes"),
            binderRows = buildRowsForGroup(report, LSPosedSignalGroup.BINDER, "Binder probes"),
            packageRows = buildRowsForGroup(report, LSPosedSignalGroup.PACKAGES, "Packages"),
            policyRows = buildRowsForGroup(report, LSPosedSignalGroup.POLICY, "SELinux policy"),
            nativeRows = buildRowsForGroup(report, LSPosedSignalGroup.NATIVE, "Native traces"),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
        )
    }
}
