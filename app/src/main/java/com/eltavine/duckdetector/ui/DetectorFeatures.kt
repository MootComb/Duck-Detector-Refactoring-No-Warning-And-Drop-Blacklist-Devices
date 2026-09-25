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

package com.eltavine.duckdetector.ui

import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.ui.detector.DetectorFeature
import com.eltavine.duckdetector.core.ui.detector.DeviceProfileFeature
import com.eltavine.duckdetector.features.bootloader.ui.BootloaderDetectorFeature
import com.eltavine.duckdetector.features.customrom.ui.CustomRomDetectorFeature
import com.eltavine.duckdetector.features.dangerousapps.ui.DangerousAppsDetectorFeature
import com.eltavine.duckdetector.features.deviceinfo.data.repository.DeviceInfoRepository
import com.eltavine.duckdetector.features.deviceinfo.ui.DeviceInfoProfileFeature
import com.eltavine.duckdetector.features.kernelcheck.ui.KernelCheckDetectorFeature
import com.eltavine.duckdetector.features.lsposed.ui.LSPosedDetectorFeature
import com.eltavine.duckdetector.features.memory.ui.MemoryDetectorFeature
import com.eltavine.duckdetector.features.mount.ui.MountDetectorFeature
import com.eltavine.duckdetector.features.nativeroot.ui.NativeRootDetectorFeature
import com.eltavine.duckdetector.features.playintegrityfix.ui.PlayIntegrityFixDetectorFeature
import com.eltavine.duckdetector.features.selinux.ui.SelinuxDetectorFeature
import com.eltavine.duckdetector.features.su.ui.SuDetectorFeature
import com.eltavine.duckdetector.features.systemproperties.ui.SystemPropertiesDetectorFeature
import com.eltavine.duckdetector.features.tee.ui.TeeDetectorFeature
import com.eltavine.duckdetector.features.virtualization.ui.VirtualizationDetectorFeature
import com.eltavine.duckdetector.features.zygisk.ui.ZygiskDetectorFeature
import com.eltavine.duckdetector.sdk.DetectorCatalog

/**
 * The dashboard card of every detector, and the device profile shown under them.
 *
 * Which detectors exist and the order their scans start come from [DetectorCatalog]. This file
 * only names each detector's card; everything central works on the sessions the cards create.
 */
internal object DetectorFeatures {
    private val cards: Map<DetectorId, DetectorFeature> = listOf(
        BootloaderDetectorFeature,
        CustomRomDetectorFeature,
        DangerousAppsDetectorFeature,
        KernelCheckDetectorFeature,
        LSPosedDetectorFeature,
        MemoryDetectorFeature,
        MountDetectorFeature,
        NativeRootDetectorFeature,
        PlayIntegrityFixDetectorFeature,
        SelinuxDetectorFeature,
        SuDetectorFeature,
        SystemPropertiesDetectorFeature,
        TeeDetectorFeature,
        VirtualizationDetectorFeature,
        ZygiskDetectorFeature,
    ).associateBy { it.id }

    /** Every detector's card, in the catalog's scan-start order. */
    val all: List<DetectorFeature> = DetectorCatalog.all.map { detector ->
        checkNotNull(cards[detector.id]) { "${detector.id} is in DetectorCatalog but has no card here" }
    }

    val deviceProfile: DeviceProfileFeature = DeviceInfoProfileFeature { context -> DeviceInfoRepository(context) }

    init {
        val uncatalogued = cards.keys - DetectorCatalog.all.map { it.id }.toSet()
        check(uncatalogued.isEmpty()) { "cards for detectors missing from DetectorCatalog: $uncatalogued" }
    }
}
