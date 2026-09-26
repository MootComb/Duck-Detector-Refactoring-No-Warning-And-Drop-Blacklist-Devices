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

public class SystemPropertyConsistencyUtils {

    public fun buildSourceMismatchSignals(
        reads: Collection<MultiSourcePropertyRead>,
    ): List<SystemPropertySignal> {
        return reads.mapNotNull { read ->
            if (!shouldEvaluateSourceMismatch(read.category)) {
                return@mapNotNull null
            }
            val populatedSources = read.sourceValues
                .mapValues { (_, value) -> sanitizeSourceValue(value) }
                .filterValues { it.isNotBlank() }
            val normalizedDistinct = populatedSources.values
                .map { normalizeForComparison(read.property, it) }
                .distinct()
            if (normalizedDistinct.size <= 1) {
                return@mapNotNull null
            }

            val severity = when {
                populatedSources.containsKey(SystemPropertySource.NATIVE_LIBC) &&
                        read.property in criticalSourceMismatchProperties -> SystemPropertySeverity.DANGER

                read.property.startsWith("ro.boot.") &&
                        populatedSources.containsKey(SystemPropertySource.NATIVE_LIBC) -> SystemPropertySeverity.DANGER

                else -> SystemPropertySeverity.WARNING
            }

            SystemPropertySignal(
                property = read.property,
                description = "Property source mismatch",
                value = "Diverged",
                category = SystemPropertyCategory.SOURCE_CONSISTENCY,
                severity = severity,
                source = read.preferredSource,
                detail = populatedSources.entries
                    .sortedBy { sourcePriority(it.key) }
                    .joinToString(separator = "\n") { (source, value) ->
                        "${sourceLabel(source)}: $value"
                    },
            )
        }
    }

    public fun buildConsistencySignals(
        readsByProperty: Map<String, MultiSourcePropertyRead>,
        nativeSnapshot: SystemPropertiesNativeSnapshot,
    ): List<SystemPropertySignal> {
        return buildList {
            addAll(buildRawBootSignals(readsByProperty, nativeSnapshot))
            addAll(buildFrameworkConsistencySignals(readsByProperty))
            addAll(buildBuildFingerprintTailSignals(readsByProperty))
            buildVerifiedBootLockSignal(readsByProperty)?.let(::add)
            buildUserBuildDebugSignal(readsByProperty)?.let(::add)
            buildPartitionVerificationSignal(readsByProperty)?.let(::add)
        }
    }

    private fun buildFrameworkConsistencySignals(
        readsByProperty: Map<String, MultiSourcePropertyRead>,
    ): List<SystemPropertySignal> {
        val findings = mutableListOf<SystemPropertySignal>()

        compareFrameworkAndProperty(
            propertyName = "ro.build.type",
            frameworkValue = Build.TYPE.orEmpty(),
            frameworkLabel = "Build.TYPE",
            readsByProperty = readsByProperty,
        )?.let(findings::add)

        compareFrameworkAndProperty(
            propertyName = "ro.build.tags",
            frameworkValue = Build.TAGS.orEmpty(),
            frameworkLabel = "Build.TAGS",
            readsByProperty = readsByProperty,
        )?.let(findings::add)

        compareFrameworkAndProperty(
            propertyName = "ro.build.fingerprint",
            frameworkValue = Build.FINGERPRINT.orEmpty(),
            frameworkLabel = "Build.FINGERPRINT",
            readsByProperty = readsByProperty,
        )?.let(findings::add)

        return findings
    }

    private fun compareFrameworkAndProperty(
        propertyName: String,
        frameworkValue: String,
        frameworkLabel: String,
        readsByProperty: Map<String, MultiSourcePropertyRead>,
    ): SystemPropertySignal? {
        val read = readsByProperty[propertyName] ?: return null
        val propertyValue = read.preferredValue
        if (frameworkValue.isBlank() || propertyValue.isBlank()) {
            return null
        }
        if (normalizeForComparison(propertyName, propertyValue) == normalizeForComparison(
                propertyName,
                frameworkValue
            )
        ) {
            return null
        }
        return SystemPropertySignal(
            property = "$propertyName <> $frameworkLabel",
            description = "Framework constant disagrees with system property",
            value = "Drift",
            category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
            severity = SystemPropertySeverity.WARNING,
            source = SystemPropertySource.BUILD,
            detail = "$propertyName=$propertyValue\n$frameworkLabel=$frameworkValue",
        )
    }

    private fun shouldEvaluateSourceMismatch(
        category: SystemPropertyCategory,
    ): Boolean {
        return category != SystemPropertyCategory.DEVICE_INFO
    }

    private fun sanitizeSourceValue(
        value: String,
    ): String {
        val trimmed = value.trim()
        return if (trimmed.contains(CALLBACK_REQUIRED_MESSAGE, ignoreCase = true)) {
            ""
        } else {
            trimmed
        }
    }

    private fun sourcePriority(
        source: SystemPropertySource,
    ): Int {
        return when (source) {
            SystemPropertySource.REFLECTION -> 0
            SystemPropertySource.GETPROP -> 1
            SystemPropertySource.NATIVE_LIBC -> 2
            SystemPropertySource.JVM -> 3
            SystemPropertySource.BUILD -> 4
            SystemPropertySource.BOOTCONFIG -> 5
            SystemPropertySource.CMDLINE -> 6
        }
    }

    private companion object {
        private val criticalSourceMismatchProperties = setOf(
            "ro.secure",
            "ro.debuggable",
            "ro.adb.secure",
            "ro.boot.verifiedbootstate",
            "ro.boot.flash.locked",
            "ro.boot.vbmeta.device_state",
            "ro.build.type",
            "ro.build.tags",
        )

        private const val CALLBACK_REQUIRED_MESSAGE =
            "Must use __system_property_read_callback() to read"
    }
}
