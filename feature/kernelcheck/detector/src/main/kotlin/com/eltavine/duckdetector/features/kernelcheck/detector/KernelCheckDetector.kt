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

package com.eltavine.duckdetector.features.kernelcheck.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.features.kernelcheck.data.repository.KernelCheckRepository
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckReport
import com.eltavine.duckdetector.features.kernelcheck.presentation.KernelCheckCardModelMapper
import com.eltavine.duckdetector.features.kernelcheck.presentation.KernelCheckDetectorId
import com.eltavine.duckdetector.features.kernelcheck.presentation.model.KernelCheckCardModel
import com.eltavine.duckdetector.features.kernelcheck.presentation.toDetectorReport

/**
 * Kernel Check: checks the kernel identity and, on arm64, the CPU identity for inconsistencies
 * between the sources that report them.
 *
 * Collected by [KernelCheckRepository], judged by `KernelCheckReport.toDetectorStatus()` in the
 * domain layer, and described by [KernelCheckCardModelMapper].
 */
public object KernelCheckDetector : Detector<KernelCheckReport, KernelCheckCardModel> {
    override val id: DetectorId = KernelCheckDetectorId

    override fun createScanner(context: Context): DetectorScanner<KernelCheckReport> = KernelCheckRepository()

    override fun loadingReport(): KernelCheckReport = KernelCheckReport.loading()

    override fun describe(report: KernelCheckReport): KernelCheckCardModel = KernelCheckCardModelMapper().map(report)

    override fun export(model: KernelCheckCardModel): DetectorReport = model.toDetectorReport()
}
