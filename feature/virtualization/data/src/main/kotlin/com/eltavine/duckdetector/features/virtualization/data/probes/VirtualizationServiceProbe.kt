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

package com.eltavine.duckdetector.features.virtualization.data.probes

import com.eltavine.duckdetector.core.platform.HiddenServiceManager
import com.eltavine.duckdetector.core.platform.PlatformFailureName
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignal
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalGroup
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity

data class VirtualizationServiceProbeResult(
    val listedServiceCount: Int,
    val signals: List<VirtualizationSignal>,
    /** Null when every ServiceManager lookup answered; otherwise names the first failure. */
    val failure: String? = null,
) {
    val available: Boolean
        get() = failure == null
}

open class VirtualizationServiceProbe {

    open fun probe(): VirtualizationServiceProbeResult {
        val listed = HiddenServiceManager.listServices()
        val qemud = HiddenServiceManager.getService("qemud")
        val virtualizationService = HiddenServiceManager.getService("android.system.virtualizationservice")
        val listedServices = listed.getOrNull().orEmpty()

        val signals = mutableListOf<VirtualizationSignal>()
        if (qemud.getOrNull() != null || listedServices.any { it.equals("qemud", ignoreCase = true) }) {
            signals += VirtualizationSignal(
                id = "virt_service_qemud",
                label = "qemud service",
                value = "Present",
                group = VirtualizationSignalGroup.RUNTIME,
                severity = VirtualizationSignalSeverity.DANGER,
                detail = "ServiceManager exposed qemud, which is a direct emulator guest service.",
            )
        }
        if (
            virtualizationService.getOrNull() != null ||
            listedServices.any { it.contains("virtualizationservice", ignoreCase = true) }
        ) {
            signals += VirtualizationSignal(
                id = "virt_service_virtualizationservice",
                label = "VirtualizationService",
                value = "Present",
                group = VirtualizationSignalGroup.ENVIRONMENT,
                severity = VirtualizationSignalSeverity.INFO,
                detail = "Capability-only service. It does not imply the current process is inside a guest.",
            )
        }

        return VirtualizationServiceProbeResult(
            listedServiceCount = listedServices.size,
            signals = signals,
            failure = listOf(listed, qemud, virtualizationService)
                .firstNotNullOfOrNull { it.exceptionOrNull() }
                ?.let(PlatformFailureName::of),
        )
    }
}
