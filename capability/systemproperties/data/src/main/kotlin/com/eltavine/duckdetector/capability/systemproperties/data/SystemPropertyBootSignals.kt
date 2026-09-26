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

package com.eltavine.duckdetector.capability.systemproperties.data

import android.os.Build
import com.eltavine.duckdetector.capability.systemproperties.domain.MultiSourcePropertyRead
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertiesNativeSnapshot
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertyCategory
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySeverity
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySignal
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySource

internal fun SystemPropertyConsistencyUtils.buildRawBootSignals(
    readsByProperty: Map<String, MultiSourcePropertyRead>,
    nativeSnapshot: SystemPropertiesNativeSnapshot,
): List<SystemPropertySignal> {
    return trackedRawBootProperties.mapNotNull { property ->
        val read = readsByProperty[property] ?: return@mapNotNull null
        val propertyValue = read.preferredValue
        if (propertyValue.isBlank()) {
            return@mapNotNull null
        }
        val (bootSource, rawValue) = nativeSnapshot.findBootValueForProperty(property)
            ?: return@mapNotNull null
        if (normalizeForComparison(property, propertyValue) == normalizeForComparison(
                property,
                rawValue
            )
        ) {
            return@mapNotNull null
        }

        SystemPropertySignal(
            property = "$property <> ${bootSourceLabel(bootSource)}",
            description = "Android property disagrees with raw boot parameter",
            value = "Contradiction",
            category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
            severity = SystemPropertySeverity.DANGER,
            source = bootSource,
            detail = buildString {
                append(property)
                append(" via ")
                append(sourceLabel(read.preferredSource))
                append(" = ")
                append(propertyValue)
                appendLine()
                append(bootSourceLabel(bootSource))
                append(" = ")
                append(rawValue)
            },
        )
    }
}

internal fun SystemPropertyConsistencyUtils.buildVerifiedBootLockSignal(
    readsByProperty: Map<String, MultiSourcePropertyRead>,
): SystemPropertySignal? {
    val verifiedBootState =
        readsByProperty["ro.boot.verifiedbootstate"]?.preferredValue.orEmpty()
    val flashLocked = readsByProperty["ro.boot.flash.locked"]?.preferredValue.orEmpty()
    val vbmetaState = readsByProperty["ro.boot.vbmeta.device_state"]?.preferredValue.orEmpty()
    if (verifiedBootState.isBlank()) {
        return null
    }

    val contradiction = when {
        verifiedBootState.equals("green", ignoreCase = true) ||
                verifiedBootState.equals("yellow", ignoreCase = true) -> {
            isUnlockedValue(flashLocked) || vbmetaState.equals("unlocked", ignoreCase = true)
        }

        verifiedBootState.equals("orange", ignoreCase = true) -> {
            isLockedValue(flashLocked) || vbmetaState.equals("locked", ignoreCase = true)
        }

        else -> false
    }

    if (!contradiction) {
        return null
    }

    return SystemPropertySignal(
        property = "Verified boot coherence",
        description = "Verified boot state conflicts with lock state",
        value = "Contradiction",
        category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
        severity = SystemPropertySeverity.DANGER,
        source = readsByProperty["ro.boot.verifiedbootstate"]?.preferredSource
            ?: SystemPropertySource.REFLECTION,
        detail = "ro.boot.verifiedbootstate=$verifiedBootState\nro.boot.flash.locked=$flashLocked\nro.boot.vbmeta.device_state=$vbmetaState",
    )
}

internal fun SystemPropertyConsistencyUtils.buildUserBuildDebugSignal(
    readsByProperty: Map<String, MultiSourcePropertyRead>,
): SystemPropertySignal? {
    val buildType = readsByProperty["ro.build.type"]?.preferredValue
        ?.takeIf { it.isNotBlank() }
        ?: Build.TYPE.orEmpty()
    val debuggable = readsByProperty["ro.debuggable"]?.preferredValue.orEmpty()
    if (!buildType.equals("user", ignoreCase = true) || debuggable != "1") {
        return null
    }

    return SystemPropertySignal(
        property = "Build profile coherence",
        description = "user build reports ro.debuggable=1",
        value = "Contradiction",
        category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
        severity = SystemPropertySeverity.DANGER,
        source = readsByProperty["ro.debuggable"]?.preferredSource
            ?: SystemPropertySource.REFLECTION,
        detail = "Effective build type=$buildType\nro.debuggable=$debuggable",
    )
}

internal fun SystemPropertyConsistencyUtils.buildPartitionVerificationSignal(
    readsByProperty: Map<String, MultiSourcePropertyRead>,
): SystemPropertySignal? {
    val verifiedBootState =
        readsByProperty["ro.boot.verifiedbootstate"]?.preferredValue.orEmpty()
    if (!verifiedBootState.equals("green", ignoreCase = true) &&
        !verifiedBootState.equals("yellow", ignoreCase = true)
    ) {
        return null
    }

    val disabled = partitionVerifiedProperties.filter { property ->
        readsByProperty[property]?.preferredValue == "0"
    }
    val logging = partitionVerifiedProperties.filter { property ->
        readsByProperty[property]?.preferredValue == "2"
    }
    if (disabled.isEmpty() && logging.isEmpty()) {
        return null
    }

    val severity = if (disabled.isNotEmpty()) {
        SystemPropertySeverity.DANGER
    } else {
        SystemPropertySeverity.WARNING
    }

    return SystemPropertySignal(
        property = "Partition verification coherence",
        description = "Verified boot state conflicts with partition dm-verity flags",
        value = if (disabled.isNotEmpty()) "Disabled" else "Logging",
        category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
        severity = severity,
        source = readsByProperty["ro.boot.verifiedbootstate"]?.preferredSource
            ?: SystemPropertySource.REFLECTION,
        detail = buildString {
            append("ro.boot.verifiedbootstate=")
            append(verifiedBootState)
            if (disabled.isNotEmpty()) {
                appendLine()
                append("Disabled partitions: ")
                append(disabled.joinToString())
            }
            if (logging.isNotEmpty()) {
                appendLine()
                append("Logging partitions: ")
                append(logging.joinToString())
            }
        },
    )
}

internal fun SystemPropertyConsistencyUtils.normalizeForComparison(
    property: String,
    value: String,
): String {
    val normalized = value.trim().lowercase()
    return if (property in booleanStyleProperties) {
        when (normalized) {
            "1", "true", "locked", "yes" -> "true"
            "0", "false", "unlocked", "no" -> "false"
            else -> normalized
        }
    } else {
        normalized
    }
}

internal fun SystemPropertyConsistencyUtils.isUnlockedValue(
    value: String,
): Boolean {
    return normalizeForComparison("lock", value) == "false"
}

internal fun SystemPropertyConsistencyUtils.isLockedValue(
    value: String,
): Boolean {
    return normalizeForComparison("lock", value) == "true"
}

internal fun SystemPropertyConsistencyUtils.sourceLabel(
    source: SystemPropertySource,
): String {
    return when (source) {
        SystemPropertySource.REFLECTION -> "Reflection"
        SystemPropertySource.GETPROP -> "getprop"
        SystemPropertySource.JVM -> "System.getProperty"
        SystemPropertySource.BUILD -> "Build constant"
        SystemPropertySource.NATIVE_LIBC -> "Native libc"
        SystemPropertySource.CMDLINE -> "/proc/cmdline"
        SystemPropertySource.BOOTCONFIG -> "/proc/bootconfig"
    }
}

internal fun SystemPropertyConsistencyUtils.bootSourceLabel(
    source: SystemPropertySource,
): String {
    return when (source) {
        SystemPropertySource.BOOTCONFIG -> "androidboot.* from /proc/bootconfig"
        SystemPropertySource.CMDLINE -> "androidboot.* from /proc/cmdline"
        else -> sourceLabel(source)
    }
}

internal val booleanStyleProperties = setOf(
    "ro.boot.flash.locked",
    "sys.oem_unlock_allowed",
    "ro.oem_unlock_supported",
    "ro.magisk.hide",
    "ro.allow.mock.location",
    "lock",
)

internal val trackedRawBootProperties = listOf(
    "ro.boot.verifiedbootstate",
    "ro.boot.flash.locked",
    "ro.boot.vbmeta.device_state",
)

internal val partitionVerifiedProperties = listOf(
    "partition.system.verified",
    "partition.vendor.verified",
    "partition.product.verified",
    "partition.system_ext.verified",
    "partition.odm.verified",
)
