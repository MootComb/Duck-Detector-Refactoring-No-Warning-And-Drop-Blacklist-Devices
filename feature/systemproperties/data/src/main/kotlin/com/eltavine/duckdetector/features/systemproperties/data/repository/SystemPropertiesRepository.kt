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

package com.eltavine.duckdetector.features.systemproperties.data.repository

import android.os.Build
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertiesNativeSnapshot
import com.eltavine.duckdetector.features.systemproperties.data.rules.SystemPropertiesCatalog
import com.eltavine.duckdetector.features.systemproperties.data.rules.SystemPropertyRule
import com.eltavine.duckdetector.capability.systemproperties.domain.MultiSourcePropertyRead
import com.eltavine.duckdetector.capability.systemproperties.data.SystemPropertyConsistencyUtils
import com.eltavine.duckdetector.capability.systemproperties.data.SystemPropertyReadUtils
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesReport
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesScanner
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesStage
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertyCategory
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySeverity
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySignal
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class SystemPropertiesRepository(
    private val readUtils: SystemPropertyReadUtils = SystemPropertyReadUtils(),
    private val consistencyUtils: SystemPropertyConsistencyUtils = SystemPropertyConsistencyUtils(),
) : SystemPropertiesScanner {
    override suspend fun scan(): SystemPropertiesReport = withContext(Dispatchers.IO) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                SystemPropertiesReport.failed(throwable.message ?: "System Properties scan failed.")
            }
    }

    private fun scanInternal(): SystemPropertiesReport {
        val trackedProperties =
            (SystemPropertiesCatalog.rules.map { it.property } + SystemPropertiesCatalog.infoProperties)
                .distinct()
        val nativeSnapshot = readUtils.collectNativeSnapshot(trackedProperties)
        val propertyCache = linkedMapOf<String, MultiSourcePropertyRead>()
        val ruleSignals = mutableListOf<SystemPropertySignal>()
        val infoSignals = mutableListOf<SystemPropertySignal>()

        SystemPropertiesCatalog.rules.forEach { rule ->
            if (rule.property == SERVICE_ADB_ROOT) {
                return@forEach
            }
            val read = readUtils.readProperty(
                property = rule.property,
                category = rule.category,
                cache = propertyCache,
                nativeSnapshot = nativeSnapshot,
            )
            if (read.preferredValue.isBlank()) {
                return@forEach
            }
            ruleSignals += buildRuleSignal(rule, read)
        }

        buildAdbRootSignal(propertyCache, nativeSnapshot)?.let(ruleSignals::add)

        SystemPropertiesCatalog.infoProperties.forEach { property ->
            val read = readUtils.readProperty(
                property = property,
                category = infoCategory(property),
                cache = propertyCache,
                nativeSnapshot = nativeSnapshot,
            )
            if (read.preferredValue.isBlank()) {
                return@forEach
            }
            if (ruleSignals.none { it.property == property }) {
                infoSignals += buildInfoSignal(property, read)
            }
        }

        val buildSignals = buildBuildConstantSignals()
        val sourceSignals = consistencyUtils.buildSourceMismatchSignals(propertyCache.values)
        val consistencySignals = consistencyUtils.buildConsistencySignals(
            readsByProperty = propertyCache,
            nativeSnapshot = nativeSnapshot,
        )
        val propAreaSignals = buildPropAreaSignals(nativeSnapshot)

        val allSignals =
            ruleSignals +
                    buildSignals +
                    sourceSignals +
                    consistencySignals +
                    propAreaSignals
        if (
            allSignals.isEmpty() &&
            infoSignals.isEmpty() &&
            !nativeSnapshot.propAreaAvailable
        ) {
            return SystemPropertiesReport.failed(
                "No readable system properties, raw boot parameters, or build constants were collected.",
            )
        }

        val observedRuleCount =
            ruleSignals.count { it.category != SystemPropertyCategory.SOURCE_CONSISTENCY }
        val reflectionHitCount = propertyCache.values.count {
            it.sourceValues[SystemPropertySource.REFLECTION].isNullOrBlank().not()
        }
        val getpropHitCount = propertyCache.values.count {
            it.sourceValues[SystemPropertySource.GETPROP].isNullOrBlank().not()
        }
        val jvmHitCount = propertyCache.values.count {
            it.sourceValues[SystemPropertySource.JVM].isNullOrBlank().not()
        }

        return SystemPropertiesReport(
            stage = SystemPropertiesStage.READY,
            signals = allSignals,
            infoSignals = infoSignals,
            checkedRuleCount = SystemPropertiesCatalog.rules.size,
            observedRuleCount = observedRuleCount,
            infoPropertyCount = infoSignals.size,
            reflectionHitCount = reflectionHitCount,
            getpropHitCount = getpropHitCount,
            jvmHitCount = jvmHitCount,
            nativeHitCount = nativeSnapshot.nativePropertyHitCount,
            bootParamHitCount = nativeSnapshot.bootParamHitCount,
            buildSignalCount = buildSignals.size,
            propAreaAvailable = nativeSnapshot.propAreaAvailable,
            propAreaContextCount = nativeSnapshot.propAreaContextCount,
            propAreaHoleCount = nativeSnapshot.propAreaHoleCount,
            methods = buildMethods(
                ruleSignals = ruleSignals,
                infoSignals = infoSignals,
                reflectionHitCount = reflectionHitCount,
                getpropHitCount = getpropHitCount,
                jvmHitCount = jvmHitCount,
                nativeHitCount = nativeSnapshot.nativePropertyHitCount,
                bootParamHitCount = nativeSnapshot.bootParamHitCount,
                observedRuleCount = observedRuleCount,
                buildSignals = buildSignals,
                sourceSignals = sourceSignals,
                consistencySignals = consistencySignals,
                propAreaSignals = propAreaSignals,
                propAreaAvailable = nativeSnapshot.propAreaAvailable,
                propAreaContextCount = nativeSnapshot.propAreaContextCount,
                propAreaHoleCount = nativeSnapshot.propAreaHoleCount,
            ),
        )
    }

    private fun buildRuleSignal(
        rule: SystemPropertyRule,
        read: MultiSourcePropertyRead,
    ): SystemPropertySignal {
        val severity = when {
            matchesDanger(rule, read.preferredValue) -> SystemPropertySeverity.DANGER
            matchesWarning(rule, read.preferredValue) -> SystemPropertySeverity.WARNING
            rule.expectedSafeValue?.equals(
                read.preferredValue,
                ignoreCase = true
            ) == true -> SystemPropertySeverity.SAFE

            else -> SystemPropertySeverity.NEUTRAL
        }

        return SystemPropertySignal(
            property = rule.property,
            description = rule.description,
            value = read.preferredValue,
            category = rule.category,
            severity = severity,
            source = read.preferredSource,
            detail = buildString {
                append(rule.description)
                append(" via ")
                append(sourceLabel(read.preferredSource))
                rule.expectedSafeValue?.let { safe ->
                    append(". Expected safe value: ")
                    append(safe)
                }
                if (read.sourceValues.count { it.value.isNotBlank() } > 1) {
                    append(". Cross-checked across ")
                    append(read.sourceValues.count { it.value.isNotBlank() })
                    append(" sources.")
                }
            },
        )
    }

    private fun buildAdbRootSignal(
        cache: MutableMap<String, MultiSourcePropertyRead>,
        nativeSnapshot: SystemPropertiesNativeSnapshot,
    ): SystemPropertySignal? {
        val adbRoot = readUtils.readProperty(
            property = SERVICE_ADB_ROOT,
            category = SystemPropertyCategory.SECURITY_CORE,
            cache = cache,
            nativeSnapshot = nativeSnapshot,
        )
        if (adbRoot.preferredValue.isBlank()) {
            return null
        }
        val debuggable = readUtils.readProperty(
            property = "ro.debuggable",
            category = SystemPropertyCategory.SECURITY_CORE,
            cache = cache,
            nativeSnapshot = nativeSnapshot,
        ).preferredValue
        val severity = when {
            adbRoot.preferredValue == "1" && debuggable == "1" -> SystemPropertySeverity.DANGER
            adbRoot.preferredValue == "1" -> SystemPropertySeverity.WARNING
            adbRoot.preferredValue == "0" -> SystemPropertySeverity.SAFE
            else -> SystemPropertySeverity.NEUTRAL
        }
        val detail = when {
            adbRoot.preferredValue == "1" && debuggable == "1" ->
                "adbd can remain root because service.adb.root=1 and ro.debuggable=1."

            adbRoot.preferredValue == "1" ->
                "service.adb.root is set, but ro.debuggable=$debuggable means adbd may not actually stay root."

            adbRoot.preferredValue == "0" ->
                "ADB root property is disabled."

            else ->
                "ADB root property is present but does not match the usual production values."
        }
        return SystemPropertySignal(
            property = SERVICE_ADB_ROOT,
            description = "ADB running as root",
            value = adbRoot.preferredValue,
            category = SystemPropertyCategory.SECURITY_CORE,
            severity = severity,
            source = adbRoot.preferredSource,
            detail = detail,
        )
    }

    private fun buildInfoSignal(
        property: String,
        read: MultiSourcePropertyRead,
    ): SystemPropertySignal {
        return SystemPropertySignal(
            property = property,
            description = friendlyInfoLabel(property),
            value = read.preferredValue,
            category = read.category,
            severity = SystemPropertySeverity.NEUTRAL,
            source = read.preferredSource,
            detail = "Collected via ${sourceLabel(read.preferredSource)}.",
        )
    }

    private fun buildBuildConstantSignals(): List<SystemPropertySignal> {
        val signals = mutableListOf<SystemPropertySignal>()

        Build.TYPE.takeIf { it.isNotBlank() }?.let { type ->
            val severity = when (type.lowercase()) {
                "eng", "userdebug" -> SystemPropertySeverity.DANGER
                "user" -> SystemPropertySeverity.SAFE
                else -> SystemPropertySeverity.NEUTRAL
            }
            signals += SystemPropertySignal(
                property = "Build.TYPE",
                description = "Build type constant",
                value = type,
                category = SystemPropertyCategory.BUILD_PROFILE,
                severity = severity,
                source = SystemPropertySource.BUILD,
                detail = "Collected from android.os.Build.TYPE.",
            )
        }

        Build.TAGS?.takeIf { it.isNotBlank() }?.let { tags ->
            val severity = when {
                tags.contains("test-keys", ignoreCase = true) ||
                        tags.contains(
                            "dev-keys",
                            ignoreCase = true
                        ) -> SystemPropertySeverity.DANGER

                tags.contains("release-keys", ignoreCase = true) -> SystemPropertySeverity.SAFE
                else -> SystemPropertySeverity.NEUTRAL
            }
            signals += SystemPropertySignal(
                property = "Build.TAGS",
                description = "Build signature tags",
                value = tags,
                category = SystemPropertyCategory.BUILD_PROFILE,
                severity = severity,
                source = SystemPropertySource.BUILD,
                detail = "Collected from android.os.Build.TAGS.",
            )
        }

        Build.FINGERPRINT.takeIf { it.isNotBlank() }?.let { fingerprint ->
            val matchedPattern =
                SystemPropertiesCatalog.suspiciousFingerprintPatterns.firstOrNull { pattern ->
                    fingerprint.contains(pattern, ignoreCase = true)
                }
            signals += SystemPropertySignal(
                property = "Build.FINGERPRINT",
                description = "Framework fingerprint constant",
                value = fingerprint,
                category = SystemPropertyCategory.BUILD_PROFILE,
                severity = if (matchedPattern != null) {
                    SystemPropertySeverity.WARNING
                } else {
                    SystemPropertySeverity.SAFE
                },
                source = SystemPropertySource.BUILD,
                detail = matchedPattern?.let { "Suspicious fingerprint pattern matched '$it'." }
                    ?: "Collected from android.os.Build.FINGERPRINT.",
            )
        }

        return signals
    }

    internal fun buildPropAreaSignals(
        nativeSnapshot: SystemPropertiesNativeSnapshot,
    ): List<SystemPropertySignal> {
        return nativeSnapshot.propAreaFindings.map { finding ->
            SystemPropertySignal(
                property = "prop_area hole: ${finding.context}",
                description = "Raw property area layout residue",
                value = "${finding.holeCount} hole(s)",
                category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
                severity = propAreaSeverity(finding.context),
                source = SystemPropertySource.NATIVE_LIBC,
                detail = buildString {
                    append("Context: ")
                    append(finding.context)
                    append(". ")
                    append(finding.detail.ifBlank { "Found hole in prop area: ${finding.context}" })
                    append(". Native /dev/__properties__ layout scan.")
                },
            )
        }
    }

    private fun matchesDanger(
        rule: SystemPropertyRule,
        value: String,
    ): Boolean {
        if (rule.dangerousValues.contains("*") && value.isNotBlank()) {
            return true
        }
        return rule.dangerousValues.any { danger ->
            danger.equals(value, ignoreCase = true)
        }
    }

    private fun matchesWarning(
        rule: SystemPropertyRule,
        value: String,
    ): Boolean {
        return rule.warningValues.any { warning ->
            warning.equals(value, ignoreCase = true)
        }
    }

    private fun infoCategory(
        property: String,
    ): SystemPropertyCategory {
        return if (property.contains("fingerprint", ignoreCase = true)) {
            SystemPropertyCategory.BUILD_FINGERPRINT
        } else {
            SystemPropertyCategory.DEVICE_INFO
        }
    }

    private fun friendlyInfoLabel(
        property: String,
    ): String {
        return when (property) {
            "ro.build.fingerprint" -> "System fingerprint"
            "ro.bootimage.build.fingerprint" -> "Boot image fingerprint"
            "ro.vendor.build.fingerprint" -> "Vendor fingerprint"
            "ro.system.build.fingerprint" -> "System partition fingerprint"
            "ro.build.display.id" -> "Build display ID"
            "ro.build.version.release" -> "Android version"
            "ro.build.version.sdk" -> "SDK level"
            "ro.build.version.security_patch" -> "Security patch"
            "ro.product.model" -> "Model"
            "ro.product.brand" -> "Brand"
            "ro.product.device" -> "Device codename"
            "ro.product.manufacturer" -> "Manufacturer"
            "ro.hardware" -> "Hardware"
            "ro.boot.vbmeta.hash_alg" -> "VBMeta hash algorithm"
            "ro.boot.vbmeta.size" -> "VBMeta size"
            "ro.boot.vbmeta.digest" -> "VBMeta digest"
            "ro.boot.avb_version" -> "AVB version"
            else -> property
        }
    }

    private fun sourceLabel(
        source: SystemPropertySource,
    ): String {
        return when (source) {
            SystemPropertySource.REFLECTION -> "reflection"
            SystemPropertySource.GETPROP -> "getprop"
            SystemPropertySource.JVM -> "System.getProperty"
            SystemPropertySource.BUILD -> "Build constant"
            SystemPropertySource.NATIVE_LIBC -> "native libc"
            SystemPropertySource.CMDLINE -> "/proc/cmdline"
            SystemPropertySource.BOOTCONFIG -> "/proc/bootconfig"
        }
    }

    private companion object {
        private const val SERVICE_ADB_ROOT = "service.adb.root"

        private fun propAreaSeverity(context: String): SystemPropertySeverity {
            val lowered = context.lowercase()
            return if ("adbd_config_prop" in lowered || "shell_prop" in lowered) {
                SystemPropertySeverity.DANGER
            } else {
                SystemPropertySeverity.WARNING
            }
        }
    }
}
