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

package com.eltavine.duckdetector.features.bootloader.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.features.bootloader.data.repository.BootloaderRepository
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderReport
import com.eltavine.duckdetector.features.bootloader.presentation.BootloaderCardModelMapper
import com.eltavine.duckdetector.features.bootloader.presentation.model.BootloaderCardModel
import com.eltavine.duckdetector.features.bootloader.presentation.toDetectorReport

/**
 * Bootloader: reads the root of trust from a KeyStore attestation and the boot-state system
 * properties, and reports what each source says about the bootloader and where they disagree.
 *
 * Collected by [BootloaderRepository], judged by `BootloaderReport.toDetectorStatus()` in the
 * domain layer, and described by [BootloaderCardModelMapper].
 */
public object BootloaderDetector : Detector<BootloaderReport, BootloaderCardModel> {
    override val id: DetectorId = DetectorId("bootloader")

    override fun createScanner(context: Context): DetectorScanner<BootloaderReport> = BootloaderRepository(context)

    override fun loadingReport(): BootloaderReport = BootloaderReport.loading()

    override fun describe(report: BootloaderReport): BootloaderCardModel = BootloaderCardModelMapper().map(report)

    override fun export(model: BootloaderCardModel): DetectorReport = model.toDetectorReport()
}
