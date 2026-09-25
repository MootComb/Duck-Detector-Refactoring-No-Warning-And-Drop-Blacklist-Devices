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

package com.eltavine.duckdetector.features.lsposed.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.features.lsposed.data.repository.LSPosedRepository
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedReport
import com.eltavine.duckdetector.features.lsposed.presentation.LSPosedCardModelMapper
import com.eltavine.duckdetector.features.lsposed.presentation.LSPosedDetectorId
import com.eltavine.duckdetector.features.lsposed.presentation.model.LSPosedCardModel
import com.eltavine.duckdetector.features.lsposed.presentation.toDetectorReport

/**
 * LSPosed: looks for LSPosed and Xposed-style hooking through class, class loader, bridge
 * field, package, stack, hook callback, Binder, zygote permission, runtime artifact, logcat and
 * SELinux policy probes.
 *
 * Collected by [LSPosedRepository], judged by `LSPosedReport.toDetectorStatus()` in the domain
 * layer, and described by [LSPosedCardModelMapper].
 */
public object LSPosedDetector : Detector<LSPosedReport, LSPosedCardModel> {
    override val id: DetectorId = LSPosedDetectorId

    override fun createScanner(context: Context): DetectorScanner<LSPosedReport> = LSPosedRepository(context)

    override fun loadingReport(): LSPosedReport = LSPosedReport.loading()

    override fun describe(report: LSPosedReport): LSPosedCardModel = LSPosedCardModelMapper().map(report)

    override fun export(model: LSPosedCardModel): DetectorReport = model.toDetectorReport()
}
