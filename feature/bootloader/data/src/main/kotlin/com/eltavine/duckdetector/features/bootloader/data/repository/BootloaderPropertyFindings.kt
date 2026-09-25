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

package com.eltavine.duckdetector.features.bootloader.data.repository

import com.eltavine.duckdetector.capability.systemproperties.domain.MultiSourcePropertyRead
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySource
import com.eltavine.duckdetector.features.bootloader.data.rules.BootloaderCatalog
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFinding
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingGroup
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingSeverity

internal fun buildPropertyFindings(
    propertyContext: BootloaderPropertyContext,
    readsByProperty: Map<String, MultiSourcePropertyRead>,
): List<BootloaderFinding> {
    return BootloaderCatalog.properties.mapNotNull { spec ->
        val read = readsByProperty[spec.property] ?: return@mapNotNull null
        val value = read.preferredValue.takeIf { it.isNotBlank() } ?: return@mapNotNull null
        BootloaderFinding(
            id = "prop_${spec.property}",
            label = propertyLabel(spec.property),
            value = propertyBadgeValue(spec.property, value),
            group = BootloaderFindingGroup.PROPERTIES,
            severity = propertySeverity(spec.property, value, propertyContext),
            detail = buildPropertyDetail(spec.property, read, propertyContext),
            detailMonospace = propertyDetailMonospace(spec.property),
        )
    }
}

private fun propertyLabel(property: String): String {
    return when (property) {
        BootloaderCatalog.FLASH_LOCKED -> "ro.boot.flash.locked"
        BootloaderCatalog.VERIFIED_BOOT_STATE -> "ro.boot.verifiedbootstate"
        BootloaderCatalog.SECURE_BOOT -> "ro.boot.secureboot"
        BootloaderCatalog.DEBUGGABLE -> "ro.debuggable"
        BootloaderCatalog.SECURE -> "ro.secure"
        BootloaderCatalog.WARRANTY_BIT,
        BootloaderCatalog.WARRANTY_BIT_ALT -> "warranty_bit"

        BootloaderCatalog.KNOX_STATE -> "ro.boot.knox.state"
        BootloaderCatalog.OEM_UNLOCK_SUPPORTED -> "ro.oem_unlock_supported"
        BootloaderCatalog.VBMETA_DEVICE_STATE -> "ro.boot.vbmeta.device_state"
        BootloaderCatalog.VERITYMODE -> "ro.boot.veritymode"
        BootloaderCatalog.VBMETA_HASH_ALG -> "ro.boot.vbmeta.hash_alg"
        BootloaderCatalog.VBMETA_SIZE -> "ro.boot.vbmeta.size"
        BootloaderCatalog.VBMETA_DIGEST -> "ro.boot.vbmeta.digest"
        BootloaderCatalog.AVB_VERSION -> "ro.boot.avb_version"
        BootloaderCatalog.VBMETA_INVALIDATE -> "ro.boot.vbmeta.invalidate_on_error"
        else -> property
    }
}

private fun propertyBadgeValue(
    property: String,
    value: String,
): String {
    return when (property) {
        BootloaderCatalog.PARTITION_SYSTEM_VERIFIED,
        BootloaderCatalog.PARTITION_VENDOR_VERIFIED,
        BootloaderCatalog.PARTITION_PRODUCT_VERIFIED,
        BootloaderCatalog.PARTITION_SYSTEM_EXT_VERIFIED,
        BootloaderCatalog.PARTITION_ODM_VERIFIED -> when (value) {
            "1" -> "Enforcing"
            "2" -> "Logging"
            "0" -> "Disabled"
            else -> value
        }

        BootloaderCatalog.WARRANTY_BIT,
        BootloaderCatalog.WARRANTY_BIT_ALT -> when (value) {
            "0" -> "Intact"
            "1" -> "Tripped"
            else -> value
        }

        else -> value
    }
}

private fun propertySeverity(
    property: String,
    value: String,
    propertyContext: BootloaderPropertyContext,
): BootloaderFindingSeverity {
    return when (property) {
        BootloaderCatalog.FLASH_LOCKED,
        BootloaderCatalog.VBMETA_DEVICE_STATE -> when {
            isLockedValue(value) -> BootloaderFindingSeverity.SAFE
            isUnlockedValue(value) -> BootloaderFindingSeverity.DANGER
            else -> BootloaderFindingSeverity.INFO
        }

        BootloaderCatalog.VERIFIED_BOOT_STATE -> when (value.lowercase()) {
            "green" -> BootloaderFindingSeverity.SAFE
            "yellow" -> BootloaderFindingSeverity.WARNING
            "orange", "red" -> BootloaderFindingSeverity.DANGER
            else -> BootloaderFindingSeverity.INFO
        }

        BootloaderCatalog.SECURE_BOOT -> if (value == "1") BootloaderFindingSeverity.SAFE else BootloaderFindingSeverity.WARNING
        BootloaderCatalog.DEBUGGABLE -> if (value == "1") BootloaderFindingSeverity.WARNING else BootloaderFindingSeverity.SAFE
        BootloaderCatalog.SECURE -> if (value == "0") BootloaderFindingSeverity.WARNING else BootloaderFindingSeverity.SAFE
        BootloaderCatalog.WARRANTY_BIT,
        BootloaderCatalog.WARRANTY_BIT_ALT -> when {
            !propertyContext.isSamsungDevice -> BootloaderFindingSeverity.INFO
            value == "1" -> BootloaderFindingSeverity.DANGER
            value == "0" -> BootloaderFindingSeverity.SAFE
            else -> BootloaderFindingSeverity.INFO
        }

        BootloaderCatalog.KNOX_STATE -> when (value.uppercase()) {
            "NORMAL" -> BootloaderFindingSeverity.SAFE
            "TRIPPED" -> BootloaderFindingSeverity.DANGER
            else -> BootloaderFindingSeverity.INFO
        }

        BootloaderCatalog.OEM_UNLOCK_SUPPORTED -> BootloaderFindingSeverity.INFO
        BootloaderCatalog.VERITYMODE -> when (value.lowercase()) {
            "enforcing", "1" -> BootloaderFindingSeverity.SAFE
            "logging", "2" -> BootloaderFindingSeverity.WARNING
            "0", "disabled" -> BootloaderFindingSeverity.DANGER
            else -> BootloaderFindingSeverity.INFO
        }

        BootloaderCatalog.VBMETA_HASH_ALG -> when (value.lowercase()) {
            "sha256", "sha512" -> BootloaderFindingSeverity.SAFE
            else -> BootloaderFindingSeverity.INFO
        }

        BootloaderCatalog.VBMETA_INVALIDATE -> when (value.lowercase()) {
            "1", "yes", "true" -> BootloaderFindingSeverity.SAFE
            "0", "no", "false" -> BootloaderFindingSeverity.WARNING
            else -> BootloaderFindingSeverity.INFO
        }

        BootloaderCatalog.PARTITION_SYSTEM_VERIFIED,
        BootloaderCatalog.PARTITION_VENDOR_VERIFIED,
        BootloaderCatalog.PARTITION_PRODUCT_VERIFIED,
        BootloaderCatalog.PARTITION_SYSTEM_EXT_VERIFIED,
        BootloaderCatalog.PARTITION_ODM_VERIFIED -> when (value) {
            "1" -> BootloaderFindingSeverity.SAFE
            "2" -> BootloaderFindingSeverity.WARNING
            "0" -> BootloaderFindingSeverity.DANGER
            else -> BootloaderFindingSeverity.INFO
        }

        BootloaderCatalog.VBMETA_DIGEST,
        BootloaderCatalog.AVB_VERSION,
        BootloaderCatalog.VBMETA_SIZE -> BootloaderFindingSeverity.INFO

        else -> BootloaderFindingSeverity.INFO
    }
}

private fun buildPropertyDetail(
    property: String,
    read: MultiSourcePropertyRead,
    propertyContext: BootloaderPropertyContext,
): String {
    val notes = mutableListOf<String>()
    notes += "Source: ${sourceLabel(read.preferredSource)}"
    when (property) {
        BootloaderCatalog.WARRANTY_BIT,
        BootloaderCatalog.WARRANTY_BIT_ALT -> {
            notes += if (propertyContext.isSamsungDevice) {
                "Samsung Knox warranty_bit is a hardware e-fuse: 0 means intact, 1 means tripped."
            } else {
                "warranty_bit is mainly meaningful on Samsung devices."
            }
        }

        BootloaderCatalog.KNOX_STATE -> {
            notes += "Samsung Knox state usually reports NORMAL or TRIPPED."
        }

        BootloaderCatalog.VBMETA_DIGEST -> {
            notes += "Compared against attested verifiedBootHash when RootOfTrust is available."
        }

        BootloaderCatalog.VERITYMODE -> {
            notes += "dm-verity modes usually map to enforcing, logging, or disabled."
        }

        BootloaderCatalog.PARTITION_SYSTEM_VERIFIED,
        BootloaderCatalog.PARTITION_VENDOR_VERIFIED,
        BootloaderCatalog.PARTITION_PRODUCT_VERIFIED,
        BootloaderCatalog.PARTITION_SYSTEM_EXT_VERIFIED,
        BootloaderCatalog.PARTITION_ODM_VERIFIED -> {
            notes += "Partition values typically map as 1=enforcing, 2=logging, 0=disabled."
        }
    }
    if (read.sourceValues.count { it.value.isNotBlank() } > 1) {
        notes += "Cross-checked across ${read.sourceValues.count { it.value.isNotBlank() }} sources."
    }
    notes += "Observed value: ${read.preferredValue}"
    return notes.joinToString(separator = "\n")
}

private fun propertyDetailMonospace(property: String): Boolean {
    return property == BootloaderCatalog.VBMETA_DIGEST ||
            property == BootloaderCatalog.VBMETA_HASH_ALG ||
            property == BootloaderCatalog.AVB_VERSION
}

private fun isLockedValue(value: String): Boolean {
    return value == "1" || value.equals("locked", ignoreCase = true) || value.equals(
        "true",
        ignoreCase = true
    )
}

private fun isUnlockedValue(value: String): Boolean {
    return value == "0" || value.equals("unlocked", ignoreCase = true) || value.equals(
        "false",
        ignoreCase = true
    )
}

internal fun sourceLabel(source: SystemPropertySource): String {
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
