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

package com.eltavine.duckdetector.features.customrom.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.features.customrom.data.repository.CustomRomRepository
import com.eltavine.duckdetector.features.customrom.domain.CustomRomReport
import com.eltavine.duckdetector.features.customrom.presentation.CustomRomCardModelMapper
import com.eltavine.duckdetector.features.customrom.presentation.model.CustomRomCardModel
import com.eltavine.duckdetector.features.customrom.presentation.toDetectorReport

/**
 * Custom ROM: looks for custom ROM traces in installed packages, build and ROM system
 * properties, and native property-area and symbol probes.
 *
 * Collected by [CustomRomRepository], judged by `CustomRomReport.toDetectorStatus()` in the
 * domain layer, and described by [CustomRomCardModelMapper].
 */
public object CustomRomDetector : Detector<CustomRomReport, CustomRomCardModel> {
    override val id: DetectorId = DetectorId("custom_rom")

    override fun createScanner(context: Context): DetectorScanner<CustomRomReport> = CustomRomRepository(context)

    override fun loadingReport(): CustomRomReport = CustomRomReport.loading()

    override fun describe(report: CustomRomReport): CustomRomCardModel = CustomRomCardModelMapper().map(report)

    override fun export(model: CustomRomCardModel): DetectorReport = model.toDetectorReport()
}
