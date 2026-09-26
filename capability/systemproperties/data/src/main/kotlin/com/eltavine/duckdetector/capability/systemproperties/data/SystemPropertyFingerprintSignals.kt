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
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertyCategory
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySeverity
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySignal
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySource

internal fun SystemPropertyConsistencyUtils.buildBuildFingerprintTailSignals(
    readsByProperty: Map<String, MultiSourcePropertyRead>,
): List<SystemPropertySignal> {
    val parsed = parseBuildFingerprint(Build.FINGERPRINT.orEmpty()) ?: return emptyList()
    val findings = mutableListOf<SystemPropertySignal>()

    if (normalizeForComparison(
            "Build.TYPE",
            Build.TYPE.orEmpty()
        ) != normalizeForComparison("Build.TYPE", parsed.type)
    ) {
        findings += SystemPropertySignal(
            property = "Build.TYPE <> fingerprint tail",
            description = "Build type disagrees with fingerprint format tail",
            value = "Type drift",
            category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
            severity = SystemPropertySeverity.WARNING,
            source = SystemPropertySource.BUILD,
            detail = "Build.TYPE=${Build.TYPE.orEmpty()}\nFingerprint type=${parsed.type}",
        )
    }

    if (normalizeForComparison(
            "Build.TAGS",
            Build.TAGS.orEmpty()
        ) != normalizeForComparison("Build.TAGS", parsed.tags)
    ) {
        findings += SystemPropertySignal(
            property = "Build.TAGS <> fingerprint tail",
            description = "Build tags disagree with fingerprint format tail",
            value = "Tags drift",
            category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
            severity = SystemPropertySeverity.WARNING,
            source = SystemPropertySource.BUILD,
            detail = "Build.TAGS=${Build.TAGS.orEmpty()}\nFingerprint tags=${parsed.tags}",
        )
    }

    val roBuildType = readsByProperty["ro.build.type"]?.preferredValue.orEmpty()
    if (roBuildType.isNotBlank() &&
        normalizeForComparison(
            "ro.build.type",
            roBuildType
        ) != normalizeForComparison("ro.build.type", parsed.type)
    ) {
        findings += SystemPropertySignal(
            property = "ro.build.type <> fingerprint tail",
            description = "ro.build.type disagrees with fingerprint format tail",
            value = "Type drift",
            category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
            severity = SystemPropertySeverity.WARNING,
            source = readsByProperty["ro.build.type"]?.preferredSource
                ?: SystemPropertySource.REFLECTION,
            detail = "ro.build.type=$roBuildType\nFingerprint type=${parsed.type}",
        )
    }

    val roBuildTags = readsByProperty["ro.build.tags"]?.preferredValue.orEmpty()
    if (roBuildTags.isNotBlank() &&
        normalizeForComparison(
            "ro.build.tags",
            roBuildTags
        ) != normalizeForComparison("ro.build.tags", parsed.tags)
    ) {
        findings += SystemPropertySignal(
            property = "ro.build.tags <> fingerprint tail",
            description = "ro.build.tags disagrees with fingerprint format tail",
            value = "Tags drift",
            category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
            severity = SystemPropertySeverity.WARNING,
            source = readsByProperty["ro.build.tags"]?.preferredSource
                ?: SystemPropertySource.REFLECTION,
            detail = "ro.build.tags=$roBuildTags\nFingerprint tags=${parsed.tags}",
        )
    }

    return findings
}

internal fun SystemPropertyConsistencyUtils.parseBuildFingerprint(
    fingerprint: String,
): ParsedBuildFingerprint? {
    if (fingerprint.isBlank()) {
        return null
    }
    val tail = fingerprint.substringAfterLast(':', missingDelimiterValue = "")
    if (tail.isBlank() || !tail.contains('/')) {
        return null
    }
    return ParsedBuildFingerprint(
        type = tail.substringBefore('/').trim(),
        tags = tail.substringAfter('/').trim(),
    )
}

internal data class ParsedBuildFingerprint(
    val type: String,
    val tags: String,
)
