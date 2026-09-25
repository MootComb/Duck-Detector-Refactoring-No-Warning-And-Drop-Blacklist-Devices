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

package com.eltavine.duckdetector.features.zygisk.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.features.zygisk.data.repository.ZygiskRepository
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskReport
import com.eltavine.duckdetector.features.zygisk.presentation.ZygiskCardModelMapper
import com.eltavine.duckdetector.features.zygisk.presentation.ZygiskDetectorId
import com.eltavine.duckdetector.features.zygisk.presentation.model.ZygiskCardModel
import com.eltavine.duckdetector.features.zygisk.presentation.toDetectorReport

/**
 * Zygisk: looks for Zygisk injection in this process through native linker, maps, file
 * descriptor, thread, seccomp and heap probes, and a file descriptor trap in a separate
 * process.
 *
 * Collected by [ZygiskRepository], judged by `ZygiskReport.toDetectorStatus()` in the domain
 * layer, and described by [ZygiskCardModelMapper].
 */
public object ZygiskDetector : Detector<ZygiskReport, ZygiskCardModel> {
    override val id: DetectorId = ZygiskDetectorId

    override fun createScanner(context: Context): DetectorScanner<ZygiskReport> = ZygiskRepository(context)

    override fun loadingReport(): ZygiskReport = ZygiskReport.loading()

    override fun describe(report: ZygiskReport): ZygiskCardModel = ZygiskCardModelMapper().map(report)

    override fun export(model: ZygiskCardModel): DetectorReport = model.toDetectorReport()
}
