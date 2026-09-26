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

package com.eltavine.duckdetector.capability.systemproperties.domain

public enum class SystemPropertySeverity {
    SAFE,
    WARNING,
    DANGER,
    NEUTRAL,
}

public enum class SystemPropertyCategory {
    SECURITY_CORE,
    VERIFIED_BOOT,
    PARTITION_VERITY,
    BUILD_PROFILE,
    ROOT_RUNTIME,
    CUSTOM_ROM,
    DEVICE_INFO,
    BUILD_FINGERPRINT,
    SOURCE_CONSISTENCY,
    PROPERTY_CONSISTENCY,
}

public enum class SystemPropertySource {
    REFLECTION,
    GETPROP,
    JVM,
    BUILD,
    NATIVE_LIBC,
    CMDLINE,
    BOOTCONFIG,
}

public data class SystemPropertySignal(
    val property: String,
    val description: String,
    val value: String,
    val category: SystemPropertyCategory,
    val severity: SystemPropertySeverity,
    val source: SystemPropertySource,
    val detail: String? = null,
)
