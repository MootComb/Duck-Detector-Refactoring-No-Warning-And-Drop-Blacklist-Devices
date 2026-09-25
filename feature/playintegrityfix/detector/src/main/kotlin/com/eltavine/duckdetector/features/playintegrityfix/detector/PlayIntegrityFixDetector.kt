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

package com.eltavine.duckdetector.features.playintegrityfix.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.features.playintegrityfix.data.repository.PlayIntegrityFixRepository
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixReport
import com.eltavine.duckdetector.features.playintegrityfix.presentation.PlayIntegrityFixCardModelMapper
import com.eltavine.duckdetector.features.playintegrityfix.presentation.model.PlayIntegrityFixCardModel
import com.eltavine.duckdetector.features.playintegrityfix.presentation.toDetectorReport

/**
 * Play Integrity Fix: looks for local traces of integrity-spoofing modules in system properties
 * and their consistency; it never returns a Google Play Integrity verdict.
 *
 * Collected by [PlayIntegrityFixRepository], judged by
 * `PlayIntegrityFixReport.toDetectorStatus()` in the domain layer, and described by
 * [PlayIntegrityFixCardModelMapper].
 */
public object PlayIntegrityFixDetector : Detector<PlayIntegrityFixReport, PlayIntegrityFixCardModel> {
    override val id: DetectorId = DetectorId("play_integrity_fix")

    override fun createScanner(context: Context): DetectorScanner<PlayIntegrityFixReport> = PlayIntegrityFixRepository()

    override fun loadingReport(): PlayIntegrityFixReport = PlayIntegrityFixReport.loading()

    override fun describe(report: PlayIntegrityFixReport): PlayIntegrityFixCardModel = PlayIntegrityFixCardModelMapper().map(report)

    override fun export(model: PlayIntegrityFixCardModel): DetectorReport = model.toDetectorReport()
}
