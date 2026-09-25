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

package com.eltavine.duckdetector.features.selinux.data.repository

import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyAnalysis
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyWeakness
import java.io.File

internal fun analyzePolicy(processContext: String?): SelinuxPolicyAnalysis {
    val details = mutableListOf<String>()
    var weaknessScore = 0

    val policyVersion = readPolicyVersion()
    val policyVersionOk = policyVersion != null && policyVersion >= MIN_EXPECTED_POLICY_VERSION
    if (policyVersion != null) {
        if (policyVersionOk) {
            details += "Policy version $policyVersion meets minimum $MIN_EXPECTED_POLICY_VERSION"
        } else {
            details += "Policy version $policyVersion is below minimum $MIN_EXPECTED_POLICY_VERSION"
            weaknessScore += 2
        }
    } else {
        details += "Policy version unreadable"
    }

    val (classCount, foundClasses) = countSecurityClasses()
    val missingClasses = EXPECTED_CLASSES.filter { expected ->
        foundClasses.none { it.equals(expected, ignoreCase = true) }
    }
    val classCountOk = classCount >= EXPECTED_CLASSES.size && missingClasses.isEmpty()
    if (classCount > 0) {
        if (classCountOk) {
            details += "Security classes look complete ($classCount)"
        } else {
            details += "Security classes missing: ${missingClasses.joinToString()}"
            weaknessScore += missingClasses.size
        }
    } else {
        details += "Security classes unreadable"
    }

    val contextType = processContext?.split(":")?.getOrNull(2)
    val dangerousTypesFound = DANGEROUS_TYPES.filter { dangerous ->
        contextType?.contains(dangerous, ignoreCase = true) == true
    }
    if (dangerousTypesFound.isNotEmpty()) {
        weaknessScore += dangerousTypesFound.size * 3
        details += "Dangerous context types: ${dangerousTypesFound.joinToString()}"
    } else if (contextType != null) {
        details += "Context type '$contextType' looks normal"
    }

    val permissiveDomains = checkPermissiveDomains(processContext)
    if (permissiveDomains.isNotEmpty()) {
        weaknessScore += permissiveDomains.size * 2
        details += "Permissive domains found: ${permissiveDomains.joinToString()}"
    } else {
        details += "No permissive domains detected"
    }

    val weakness = when {
        weaknessScore >= 5 -> SelinuxPolicyWeakness.SEVERE
        weaknessScore >= 3 -> SelinuxPolicyWeakness.MODERATE
        weaknessScore >= 1 -> SelinuxPolicyWeakness.MINOR
        else -> SelinuxPolicyWeakness.NONE
    }

    return SelinuxPolicyAnalysis(
        policyVersion = policyVersion,
        policyVersionOk = policyVersionOk,
        classCount = classCount,
        classCountOk = classCountOk,
        foundClasses = foundClasses,
        missingClasses = missingClasses,
        dangerousTypesFound = dangerousTypesFound,
        permissiveDomains = permissiveDomains,
        processContext = processContext,
        contextType = contextType,
        weakness = weakness,
        details = details,
    )
}

private fun readPolicyVersion(): Int? {
    return try {
        val file = File(SELINUX_POLICY_VERSION_PATH)
        if (file.exists() && file.canRead()) {
            file.readText().trim().toIntOrNull()
        } else {
            null
        }
    } catch (_: Exception) {
        null
    }
}

private fun countSecurityClasses(): Pair<Int, List<String>> {
    return try {
        val classDir = File(SELINUX_CLASS_PATH)
        if (classDir.exists() && classDir.isDirectory) {
            val classes = classDir.listFiles()
                ?.filter { it.isDirectory }
                ?.map { it.name }
                .orEmpty()
            classes.size to classes
        } else {
            0 to emptyList()
        }
    } catch (_: Exception) {
        0 to emptyList()
    }
}

private fun checkPermissiveDomains(processContext: String?): List<String> {
    if (processContext.isNullOrBlank()) {
        return emptyList()
    }
    return if (processContext.contains("permissive", ignoreCase = true)) {
        listOf(processContext.split(":").getOrNull(2) ?: "unknown")
    } else {
        emptyList()
    }
}

private const val MIN_EXPECTED_POLICY_VERSION = 28

private val DANGEROUS_TYPES = listOf(
    "su",
    "supersu",
    "magisk",
    "permissive",
    "unconfined",
    "shell",
)

private val EXPECTED_CLASSES = listOf(
    "file",
    "dir",
    "process",
    "capability",
    "socket",
    "binder",
)

private const val SELINUX_POLICY_VERSION_PATH = "/sys/fs/selinux/policyvers"
private const val SELINUX_CLASS_PATH = "/sys/fs/selinux/class"
