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

package com.eltavine.duckdetector.features.systemproperties.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.detector.DetectorSpecificApi
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.features.systemproperties.data.repository.SystemPropertiesRepository
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesReport
import com.eltavine.duckdetector.features.systemproperties.presentation.SystemPropertiesCardModelMapper
import com.eltavine.duckdetector.features.systemproperties.presentation.model.SystemPropertiesCardModel
import com.eltavine.duckdetector.features.systemproperties.presentation.toDetectorReport

/**
 * System Properties: reads security-relevant system properties from several sources and reports
 * values and inconsistencies that suggest they were modified.
 *
 * Collected by [SystemPropertiesRepository], judged by
 * `SystemPropertiesReport.toDetectorStatus()` in the domain layer, and described by
 * [SystemPropertiesCardModelMapper].
 */
@DetectorSpecificApi
public object SystemPropertiesDetector : Detector<SystemPropertiesReport, SystemPropertiesCardModel> {
    override val id: DetectorId = DetectorId("system_properties")

    override fun createScanner(context: Context): DetectorScanner<SystemPropertiesReport> = SystemPropertiesRepository()

    override fun loadingReport(): SystemPropertiesReport = SystemPropertiesReport.loading()

    override fun describe(report: SystemPropertiesReport): SystemPropertiesCardModel = SystemPropertiesCardModelMapper().map(report)

    override fun export(model: SystemPropertiesCardModel): DetectorReport = model.toDetectorReport()
}
