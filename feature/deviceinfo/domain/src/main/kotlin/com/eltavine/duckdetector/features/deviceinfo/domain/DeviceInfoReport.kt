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

package com.eltavine.duckdetector.features.deviceinfo.domain

enum class DeviceInfoStage {
    LOADING,
    READY,
    FAILED,
}

/** The sections of the device profile, in the order it lists them. */
enum class DeviceInfoSectionKind(val title: String) {
    IDENTITY("Identity"),
    BUILD("Build"),
    ANDROID("Android"),
    RUNTIME("Runtime"),
    CONTEXT("Context"),
}

/** The entries the profile's header summarises. */
enum class DeviceInfoKey {
    BRAND,
    MODEL,
    ANDROID_RELEASE,
    SDK,
}

data class DeviceInfoEntry(
    val label: String,
    val value: String,
    val detailMonospace: Boolean = false,
    val key: DeviceInfoKey? = null,
)

data class DeviceInfoSection(
    val kind: DeviceInfoSectionKind,
    val entries: List<DeviceInfoEntry>,
) {
    val title: String get() = kind.title
}

data class DeviceInfoReport(
    val stage: DeviceInfoStage,
    val sections: List<DeviceInfoSection>,
    val errorMessage: String? = null,
) {
    val totalCount: Int
        get() = sections.sumOf { it.entries.size }

    companion object {
        fun loading(): DeviceInfoReport {
            return DeviceInfoReport(
                stage = DeviceInfoStage.LOADING,
                sections = emptyList(),
            )
        }

        fun failed(message: String): DeviceInfoReport {
            return DeviceInfoReport(
                stage = DeviceInfoStage.FAILED,
                sections = emptyList(),
                errorMessage = message,
            )
        }
    }
}
