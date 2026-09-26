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

package com.eltavine.duckdetector.features.selinux.detector

import android.content.Context
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.detector.DetectorSpecificApi
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.features.selinux.data.repository.SelinuxRepository
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.presentation.SelinuxCardModelMapper
import com.eltavine.duckdetector.features.selinux.presentation.model.SelinuxCardModel
import com.eltavine.duckdetector.features.selinux.presentation.toDetectorReport

/**
 * SELinux: checks the SELinux state visible to the app: audit behaviour, context validity
 * checked from an app zygote carrier, and signs of a modified policy.
 *
 * Collected by [SelinuxRepository], judged by `SelinuxReport.toDetectorStatus()` in the domain
 * layer, and described by [SelinuxCardModelMapper].
 */
@DetectorSpecificApi
public object SelinuxDetector : Detector<SelinuxReport, SelinuxCardModel> {
    override val id: DetectorId = DetectorId("selinux")

    override fun createScanner(context: Context): DetectorScanner<SelinuxReport> = SelinuxRepository(context)

    override fun loadingReport(): SelinuxReport = SelinuxReport.loading()

    override fun describe(report: SelinuxReport): SelinuxCardModel = SelinuxCardModelMapper().map(report)

    override fun export(model: SelinuxCardModel): DetectorReport = model.toDetectorReport()
}
