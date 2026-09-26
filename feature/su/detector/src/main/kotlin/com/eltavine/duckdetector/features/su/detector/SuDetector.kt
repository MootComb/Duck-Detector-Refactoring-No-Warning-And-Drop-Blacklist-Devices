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

package com.eltavine.duckdetector.features.su.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.detector.DetectorSpecificApi
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.features.su.data.repository.SuRepository
import com.eltavine.duckdetector.features.su.domain.SuReport
import com.eltavine.duckdetector.features.su.presentation.SuCardModelMapper
import com.eltavine.duckdetector.features.su.presentation.model.SuCardModel
import com.eltavine.duckdetector.features.su.presentation.toDetectorReport

/**
 * SU: looks for su binaries and root daemons on known paths and in PATH, an abnormal SELinux
 * context of this process, and suspicious processes from a native process scan.
 *
 * Collected by [SuRepository], judged by `SuReport.toDetectorStatus()` in the domain layer, and
 * described by [SuCardModelMapper].
 */
@DetectorSpecificApi
public object SuDetector : Detector<SuReport, SuCardModel> {
    override val id: DetectorId = DetectorId("su")

    override fun createScanner(context: Context): DetectorScanner<SuReport> = SuRepository()

    override fun loadingReport(): SuReport = SuReport.loading()

    override fun describe(report: SuReport): SuCardModel = SuCardModelMapper().map(report)

    override fun export(model: SuCardModel): DetectorReport = model.toDetectorReport()
}
