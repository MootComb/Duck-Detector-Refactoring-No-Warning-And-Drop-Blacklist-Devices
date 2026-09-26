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

package com.eltavine.duckdetector.features.memory.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.detector.DetectorSpecificApi
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.features.memory.data.repository.MemoryRepository
import com.eltavine.duckdetector.features.memory.domain.MemoryReport
import com.eltavine.duckdetector.features.memory.presentation.MemoryCardModelMapper
import com.eltavine.duckdetector.features.memory.presentation.model.MemoryCardModel
import com.eltavine.duckdetector.features.memory.presentation.toDetectorReport

/**
 * Memory: inspects this process natively for function hooks, memory map anomalies, file
 * descriptors, signal handlers, and vDSO and dynamic linker tampering.
 *
 * Collected by [MemoryRepository], judged by `MemoryReport.toDetectorStatus()` in the domain
 * layer, and described by [MemoryCardModelMapper].
 */
@DetectorSpecificApi
public object MemoryDetector : Detector<MemoryReport, MemoryCardModel> {
    override val id: DetectorId = DetectorId("memory")

    override fun createScanner(context: Context): DetectorScanner<MemoryReport> = MemoryRepository()

    override fun loadingReport(): MemoryReport = MemoryReport.loading()

    override fun describe(report: MemoryReport): MemoryCardModel = MemoryCardModelMapper().map(report)

    override fun export(model: MemoryCardModel): DetectorReport = model.toDetectorReport()
}
