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

package com.eltavine.duckdetector.features.deviceinfo.presentation.model

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.features.deviceinfo.domain.DeviceInfoSectionKind

data class DeviceInfoCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<DeviceInfoHeaderFactModel>,
    val sections: List<DeviceInfoSectionModel>,
)

/** The facts in the profile's header, in the order the export lists them. */
enum class DeviceInfoHeaderFact(val label: String) {
    BRAND("Brand"),
    MODEL("Model"),
    ANDROID("Android"),
    SDK("SDK"),
}

data class DeviceInfoHeaderFactModel(
    val fact: DeviceInfoHeaderFact,
    val value: String,
) {
    val label: String get() = fact.label
}

data class DeviceInfoSectionModel(
    val title: String,
    val rows: List<DeviceInfoRowModel>,
    /** The profile section this is; null for the section that explains a failed collection. */
    val kind: DeviceInfoSectionKind? = null,
)

data class DeviceInfoRowModel(
    val label: String,
    val value: String,
    val detailMonospace: Boolean = false,
)
