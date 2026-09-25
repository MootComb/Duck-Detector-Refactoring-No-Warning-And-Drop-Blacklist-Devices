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
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySeverity
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySignal
import com.eltavine.duckdetector.features.systemproperties.data.rules.SystemPropertiesCatalog
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesMethodOutcome
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesMethodResult

internal fun buildMethods(
    ruleSignals: List<SystemPropertySignal>,
    infoSignals: List<SystemPropertySignal>,
    reflectionHitCount: Int,
    getpropHitCount: Int,
    jvmHitCount: Int,
    nativeHitCount: Int,
    bootParamHitCount: Int,
    observedRuleCount: Int,
    buildSignals: List<SystemPropertySignal>,
    sourceSignals: List<SystemPropertySignal>,
    consistencySignals: List<SystemPropertySignal>,
    propAreaSignals: List<SystemPropertySignal>,
    propAreaAvailable: Boolean,
    propAreaContextCount: Int,
    propAreaHoleCount: Int,
): List<SystemPropertiesMethodResult> {
    val buildDangerCount = buildSignals.count { it.severity == SystemPropertySeverity.DANGER }
    val buildWarningCount = buildSignals.count { it.severity == SystemPropertySeverity.WARNING }
    val sourceDangerCount = sourceSignals.count { it.severity == SystemPropertySeverity.DANGER }
    val consistencyDangerCount =
        consistencySignals.count { it.severity == SystemPropertySeverity.DANGER }

    return listOf(
        SystemPropertiesMethodResult(
            label = "Reflection API",
            summary = if (reflectionHitCount > 0) "$reflectionHitCount hit(s)" else "Unavailable",
            outcome = if (reflectionHitCount > 0) {
                SystemPropertiesMethodOutcome.CLEAN
            } else {
                SystemPropertiesMethodOutcome.SUPPORT
            },
            detail = "android.os.SystemProperties reflection reads.",
        ),
        SystemPropertiesMethodResult(
            label = "getprop snapshot",
            summary = if (getpropHitCount > 0) "$getpropHitCount hit(s)" else "Unavailable",
            outcome = if (getpropHitCount > 0) {
                SystemPropertiesMethodOutcome.CLEAN
            } else {
                SystemPropertiesMethodOutcome.SUPPORT
            },
            detail = "Single getprop dump parsed once and reused for cross-checks.",
        ),
        SystemPropertiesMethodResult(
            label = "JVM property fallback",
            summary = if (jvmHitCount > 0) "$jvmHitCount fallback(s)" else "Not needed",
            outcome = if (jvmHitCount > 0) {
                SystemPropertiesMethodOutcome.SUPPORT
            } else {
                SystemPropertiesMethodOutcome.CLEAN
            },
            detail = "System.getProperty fallback reads.",
        ),
        SystemPropertiesMethodResult(
            label = "Native libc",
            summary = if (nativeHitCount > 0) "$nativeHitCount hit(s)" else "Unavailable",
            outcome = if (nativeHitCount > 0) {
                SystemPropertiesMethodOutcome.CLEAN
            } else {
                SystemPropertiesMethodOutcome.SUPPORT
            },
            detail = "Native libc property cross-checks using the callback-based system property API.",
        ),
        SystemPropertiesMethodResult(
            label = "Raw boot params",
            summary = if (bootParamHitCount > 0) "$bootParamHitCount hit(s)" else "Unavailable",
            outcome = if (bootParamHitCount > 0) {
                SystemPropertiesMethodOutcome.CLEAN
            } else {
                SystemPropertiesMethodOutcome.SUPPORT
            },
            detail = "androidboot.* values from /proc/cmdline and /proc/bootconfig.",
        ),
        SystemPropertiesMethodResult(
            label = "Build constants",
            summary = when {
                buildDangerCount > 0 -> "$buildDangerCount danger"
                buildWarningCount > 0 -> "$buildWarningCount warning"
                buildSignals.isNotEmpty() -> "Clean"
                else -> "Unavailable"
            },
            outcome = when {
                buildDangerCount > 0 -> SystemPropertiesMethodOutcome.DANGER
                buildWarningCount > 0 -> SystemPropertiesMethodOutcome.WARNING
                buildSignals.isNotEmpty() -> SystemPropertiesMethodOutcome.CLEAN
                else -> SystemPropertiesMethodOutcome.SUPPORT
            },
            detail = "Build.TYPE, Build.TAGS, and Build.FINGERPRINT checks.",
        ),
        SystemPropertiesMethodResult(
            label = "Source consistency",
            summary = when {
                sourceDangerCount > 0 -> "$sourceDangerCount danger"
                sourceSignals.isNotEmpty() -> "${sourceSignals.size} mismatch(es)"
                else -> "Aligned"
            },
            outcome = when {
                sourceDangerCount > 0 -> SystemPropertiesMethodOutcome.DANGER
                sourceSignals.isNotEmpty() -> SystemPropertiesMethodOutcome.WARNING
                nativeHitCount > 0 || reflectionHitCount > 0 || getpropHitCount > 0 -> SystemPropertiesMethodOutcome.CLEAN
                else -> SystemPropertiesMethodOutcome.SUPPORT
            },
            detail = "Cross-source comparison across reflection, getprop, JVM, and native libc reads.",
        ),
        SystemPropertiesMethodResult(
            label = "Cross-check rules",
            summary = when {
                consistencyDangerCount > 0 -> "$consistencyDangerCount danger"
                consistencySignals.isNotEmpty() -> "${consistencySignals.size} warning(s)"
                else -> "Aligned"
            },
            outcome = when {
                consistencyDangerCount > 0 -> SystemPropertiesMethodOutcome.DANGER
                consistencySignals.isNotEmpty() -> SystemPropertiesMethodOutcome.WARNING
                else -> SystemPropertiesMethodOutcome.CLEAN
            },
            detail = "Framework-vs-property, fingerprint-tail, raw-boot, and lock-state coherence checks.",
        ),
        buildPropAreaMethod(
            propAreaAvailable = propAreaAvailable,
            propAreaContextCount = propAreaContextCount,
            propAreaHoleCount = propAreaHoleCount,
            propAreaSignals = propAreaSignals,
        ),
        SystemPropertiesMethodResult(
            label = "Property catalog",
            summary = "$observedRuleCount / ${SystemPropertiesCatalog.rules.size} observed",
            outcome = when {
                ruleSignals.any { it.severity == SystemPropertySeverity.DANGER } -> SystemPropertiesMethodOutcome.DANGER
                ruleSignals.any { it.severity == SystemPropertySeverity.WARNING } -> SystemPropertiesMethodOutcome.WARNING
                observedRuleCount > 0 || infoSignals.isNotEmpty() -> SystemPropertiesMethodOutcome.CLEAN
                else -> SystemPropertiesMethodOutcome.SUPPORT
            },
            detail = "Security rule matches plus ${infoSignals.size} info-only properties.",
        ),
    )
}

internal fun buildPropAreaMethod(
    propAreaAvailable: Boolean,
    propAreaContextCount: Int,
    propAreaHoleCount: Int,
    propAreaSignals: List<SystemPropertySignal>,
): SystemPropertiesMethodResult {
    return SystemPropertiesMethodResult(
        label = "Prop area layout",
        summary = when {
            !propAreaAvailable -> "Unavailable"
            propAreaHoleCount > 0 -> "$propAreaHoleCount hole(s)"
            else -> "Clean"
        },
        outcome = when {
            propAreaSignals.any { it.severity == SystemPropertySeverity.DANGER } -> SystemPropertiesMethodOutcome.DANGER
            propAreaSignals.isNotEmpty() -> SystemPropertiesMethodOutcome.WARNING
            propAreaAvailable -> SystemPropertiesMethodOutcome.CLEAN
            else -> SystemPropertiesMethodOutcome.SUPPORT
        },
        detail = if (propAreaAvailable) {
            "Raw /dev/__properties__ layout scan across $propAreaContextCount area(s)."
        } else {
            "Raw /dev/__properties__ layout scan unavailable."
        },
    )
}
