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

package com.eltavine.duckdetector.features.tee.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.features.tee.data.repository.TeeRepository
import com.eltavine.duckdetector.features.tee.domain.TeeReport
import com.eltavine.duckdetector.features.tee.presentation.TeeCardModelMapper
import com.eltavine.duckdetector.features.tee.presentation.TeeDetectorId
import com.eltavine.duckdetector.features.tee.presentation.model.TeeCardModel
import com.eltavine.duckdetector.features.tee.presentation.toDetectorReport

/**
 * TEE: evaluates Android KeyStore and attestation evidence: certificate chains, security
 * levels, revocation status and selected KeyMint, StrongBox and Soter behaviour, together with
 * native timing and environment probes.
 *
 * Collected by [TeeRepository], judged by `TeeReport.toDetectorStatus()` in the domain layer,
 * and described by [TeeCardModelMapper].
 *
 * The card model is described collapsed; expansion only changes the card, never the export.
 */
public object TeeDetector : Detector<TeeReport, TeeCardModel> {
    override val id: DetectorId = TeeDetectorId

    override fun createScanner(context: Context): DetectorScanner<TeeReport> = TeeRepository(context)

    override fun loadingReport(): TeeReport = TeeReport.loading()

    override fun describe(report: TeeReport): TeeCardModel = TeeCardModelMapper().map(report, isExpanded = false)

    override fun export(model: TeeCardModel): DetectorReport = model.toDetectorReport()
}
