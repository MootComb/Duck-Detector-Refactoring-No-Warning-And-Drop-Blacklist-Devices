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

package com.eltavine.duckdetector.features.dashboard.data

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.core.scan.DetectorSummary
import com.eltavine.duckdetector.features.bootloader.presentation.toDetectorReport
import com.eltavine.duckdetector.features.bootloader.ui.model.BootloaderCardModel
import com.eltavine.duckdetector.features.customrom.presentation.toDetectorReport
import com.eltavine.duckdetector.features.customrom.presentation.model.CustomRomCardModel
import com.eltavine.duckdetector.features.dangerousapps.presentation.toDetectorReport
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsCardModel
import com.eltavine.duckdetector.features.dashboard.ui.model.buildDashboardFindings
import com.eltavine.duckdetector.features.dashboard.ui.model.buildDashboardOverview
import com.eltavine.duckdetector.features.deviceinfo.presentation.toDeviceReport
import com.eltavine.duckdetector.features.deviceinfo.ui.model.DeviceInfoCardModel
import com.eltavine.duckdetector.features.deviceinfo.ui.model.DeviceInfoHeaderFactModel
import com.eltavine.duckdetector.features.kernelcheck.presentation.toDetectorReport
import com.eltavine.duckdetector.features.kernelcheck.presentation.model.KernelCheckCardModel
import com.eltavine.duckdetector.features.lsposed.presentation.toDetectorReport
import com.eltavine.duckdetector.features.lsposed.ui.model.LSPosedCardModel
import com.eltavine.duckdetector.features.memory.presentation.toDetectorReport
import com.eltavine.duckdetector.features.memory.presentation.model.MemoryCardModel
import com.eltavine.duckdetector.features.mount.presentation.toDetectorReport
import com.eltavine.duckdetector.features.mount.ui.model.MountCardModel
import com.eltavine.duckdetector.features.nativeroot.presentation.toDetectorReport
import com.eltavine.duckdetector.features.nativeroot.ui.model.NativeRootCardModel
import com.eltavine.duckdetector.features.playintegrityfix.presentation.toDetectorReport
import com.eltavine.duckdetector.features.playintegrityfix.presentation.model.PlayIntegrityFixCardModel
import com.eltavine.duckdetector.features.selinux.presentation.toDetectorReport
import com.eltavine.duckdetector.features.selinux.ui.model.SelinuxCardModel
import com.eltavine.duckdetector.features.su.presentation.toDetectorReport
import com.eltavine.duckdetector.features.su.presentation.model.SuCardModel
import com.eltavine.duckdetector.features.systemproperties.presentation.toDetectorReport
import com.eltavine.duckdetector.features.systemproperties.ui.model.SystemPropertiesCardModel
import com.eltavine.duckdetector.features.tee.presentation.toDetectorReport
import com.eltavine.duckdetector.features.tee.ui.model.TeeCardModel
import com.eltavine.duckdetector.features.virtualization.presentation.toDetectorReport
import com.eltavine.duckdetector.features.virtualization.ui.model.VirtualizationCardModel
import com.eltavine.duckdetector.features.zygisk.presentation.toDetectorReport
import com.eltavine.duckdetector.features.zygisk.presentation.model.ZygiskCardModel

/** One fully populated dashboard export built from generated card models. */
internal class ExportScenario(seed: Int, withScanTime: Boolean = false, minListSize: Int = 0) {

    private val fixtures = CardFixtures(seed, minListSize)
    private val reports: List<DetectorReport> = listOf(
        fixtures.create(BootloaderCardModel::class.java).toDetectorReport(),
        fixtures.create(CustomRomCardModel::class.java).toDetectorReport(),
        fixtures.create(DangerousAppsCardModel::class.java).toDetectorReport(),
        fixtures.create(KernelCheckCardModel::class.java).toDetectorReport(),
        fixtures.create(LSPosedCardModel::class.java).toDetectorReport(),
        fixtures.create(MemoryCardModel::class.java).toDetectorReport(),
        fixtures.create(MountCardModel::class.java).toDetectorReport(),
        fixtures.create(NativeRootCardModel::class.java).toDetectorReport(),
        fixtures.create(PlayIntegrityFixCardModel::class.java).toDetectorReport(),
        fixtures.create(SelinuxCardModel::class.java).toDetectorReport(),
        fixtures.create(SuCardModel::class.java).toDetectorReport(),
        fixtures.create(SystemPropertiesCardModel::class.java).toDetectorReport(),
        fixtures.create(TeeCardModel::class.java).toDetectorReport(),
        fixtures.create(VirtualizationCardModel::class.java).toDetectorReport(),
        fixtures.create(ZygiskCardModel::class.java).toDetectorReport(),
    )
    private val device = fixtures.create(DeviceInfoCardModel::class.java).let { generated ->
        val identity = when (seed % 3) {
            1 -> listOf(fact("Brand", "Duck"), fact("Model", "Pond 7"), fact("Android", "17"), fact("SDK", "37"))
            2 -> listOf(fact("brand", "Duck"), fact("MODEL", "Pond 7"), fact("Android", "17"))
            else -> emptyList()
        }
        generated.copy(headerFacts = identity + generated.headerFacts)
    }
    private val summaries = reports.mapIndexed { index, report ->
        DetectorSummary(
            id = DetectorId("detector_$index"),
            title = report.title,
            status = DetectorStatus(report.severity, if (report.severity == DetectionSeverity.INFO) InfoKind.ERROR else null),
            headline = report.verdict,
            summary = "Summary for ${report.title}",
            ready = index % 5 != 4,
        )
    }
    private val overview = buildDashboardOverview(
        contributions = summaries,
        scanDurationMillis = if (withScanTime) 1_234L else null,
        scanCompletedAtEpochMillis = if (withScanTime) 1_700_000_000_000L else null,
    )
    private val findings = buildDashboardFindings(summaries)

    fun export(header: ExportHeader): DashboardExport = DashboardExport(
        header = header,
        overview = overview,
        topFindings = findings,
        detectors = reports,
        device = device.toDeviceReport(),
    )

    private fun fact(label: String, value: String) = DeviceInfoHeaderFactModel(label, value)
}
