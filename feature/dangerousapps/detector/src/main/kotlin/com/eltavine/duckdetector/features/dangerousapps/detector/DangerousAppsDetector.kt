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

package com.eltavine.duckdetector.features.dangerousapps.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.features.dangerousapps.data.repository.DangerousAppsRepository
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsCatalog
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsReport
import com.eltavine.duckdetector.features.dangerousapps.presentation.DangerousAppsCardModelMapper
import com.eltavine.duckdetector.features.dangerousapps.presentation.DangerousAppsDetectorId
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsCardModel
import com.eltavine.duckdetector.features.dangerousapps.presentation.toDetectorReport

/**
 * Dangerous Apps: checks whether known root, hooking and tampering apps are installed, using
 * the package inventory and side channels that reveal packages the inventory cannot see.
 *
 * Collected by [DangerousAppsRepository], judged by `DangerousAppsReport.toDetectorStatus()` in
 * the domain layer, and described by [DangerousAppsCardModelMapper].
 */
public object DangerousAppsDetector : Detector<DangerousAppsReport, DangerousAppsCardModel> {
    override val id: DetectorId = DangerousAppsDetectorId

    override fun createScanner(context: Context): DetectorScanner<DangerousAppsReport> = DangerousAppsRepository(context)

    override fun loadingReport(): DangerousAppsReport = DangerousAppsReport.loading(DangerousAppsCatalog.targets)

    override fun describe(report: DangerousAppsReport): DangerousAppsCardModel = DangerousAppsCardModelMapper().map(report)

    override fun export(model: DangerousAppsCardModel): DetectorReport = model.toDetectorReport()
}
