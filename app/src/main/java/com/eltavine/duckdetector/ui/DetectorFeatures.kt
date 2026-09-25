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

import com.eltavine.duckdetector.core.detector.DetectorFeature
import com.eltavine.duckdetector.core.detector.DeviceProfileFeature
import com.eltavine.duckdetector.features.bootloader.ui.BootloaderDetectorFeature
import com.eltavine.duckdetector.features.customrom.ui.CustomRomDetectorFeature
import com.eltavine.duckdetector.features.dangerousapps.ui.DangerousAppsDetectorFeature
import com.eltavine.duckdetector.features.deviceinfo.ui.DeviceInfoProfileFeature
import com.eltavine.duckdetector.features.kernelcheck.ui.KernelCheckDetectorFeature
import com.eltavine.duckdetector.features.lsposed.ui.LSPosedDetectorFeature
import com.eltavine.duckdetector.features.memory.ui.MemoryDetectorFeature
import com.eltavine.duckdetector.features.mount.ui.MountDetectorFeature
import com.eltavine.duckdetector.features.nativeroot.ui.NativeRootDetectorFeature
import com.eltavine.duckdetector.features.playintegrityfix.ui.PlayIntegrityFixDetectorFeature
import com.eltavine.duckdetector.features.selinux.ui.SelinuxDetectorFeature
import com.eltavine.duckdetector.features.su.data.repository.SuRepository
import com.eltavine.duckdetector.features.su.ui.SuDetectorFeature
import com.eltavine.duckdetector.features.systemproperties.ui.SystemPropertiesDetectorFeature
import com.eltavine.duckdetector.features.tee.ui.TeeDetectorFeature
import com.eltavine.duckdetector.features.virtualization.ui.VirtualizationDetectorFeature
import com.eltavine.duckdetector.features.zygisk.ui.ZygiskDetectorFeature

/**
 * Every detector the application composes, each bound to the platform adapters it scans through.
 *
 * This is the one place that names every detector; central code works on the sessions these
 * features create.
 */
internal object DetectorFeatures {
    val bootloader: DetectorFeature = BootloaderDetectorFeature
    val tee: DetectorFeature = TeeDetectorFeature
    val customRom: DetectorFeature = CustomRomDetectorFeature
    val dangerousApps: DetectorFeature = DangerousAppsDetectorFeature
    val kernelCheck: DetectorFeature = KernelCheckDetectorFeature
    val lsposed: DetectorFeature = LSPosedDetectorFeature
    val memory: DetectorFeature = MemoryDetectorFeature
    val mount: DetectorFeature = MountDetectorFeature
    val nativeRoot: DetectorFeature = NativeRootDetectorFeature
    val playIntegrityFix: DetectorFeature = PlayIntegrityFixDetectorFeature
    val selinux: DetectorFeature = SelinuxDetectorFeature
    val su: DetectorFeature = SuDetectorFeature { SuRepository() }
    val systemProperties: DetectorFeature = SystemPropertiesDetectorFeature
    val virtualization: DetectorFeature = VirtualizationDetectorFeature
    val zygisk: DetectorFeature = ZygiskDetectorFeature
    val deviceProfile: DeviceProfileFeature = DeviceInfoProfileFeature
}
