/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

package com.eltavine.duckdetector.features.update.data

import com.eltavine.duckdetector.features.update.domain.MAX_UPDATE_APK_BYTES
import com.eltavine.duckdetector.features.update.domain.NightlyUpdateApk
import com.eltavine.duckdetector.features.update.domain.NightlyUpdateCommit
import com.eltavine.duckdetector.features.update.domain.NightlyUpdateManifest
import java.time.Instant
import org.json.JSONObject

class UpdateManifestValidationException(message: String) : IllegalArgumentException(message)

class UpdateManifestParser {

    fun parse(rawJson: String): NightlyUpdateManifest {
        val root = runCatching { JSONObject(rawJson) }
            .getOrElse { throw UpdateManifestValidationException("Update manifest is not valid JSON.") }
        val schemaVersion = root.requirePositiveInt("schemaVersion")
        if (schemaVersion != SUPPORTED_SCHEMA_VERSION) {
            throw UpdateManifestValidationException("Unsupported update manifest schema: $schemaVersion")
        }

        val channel = root.requireNonBlankString("channel")
        if (channel != EXPECTED_CHANNEL) {
            throw UpdateManifestValidationException("Unexpected update channel: $channel")
        }
        val branch = root.requireNonBlankString("branch")
        if (branch !in EXPECTED_BRANCHES) {
            throw UpdateManifestValidationException("Unexpected update branch: $branch")
        }

        val commitJson = root.requireObject("commit")
        val commitSha = commitJson.requireNonBlankString("sha").lowercase()
        if (!FULL_SHA_REGEX.matches(commitSha)) {
            throw UpdateManifestValidationException("Update commit SHA must contain 40 hexadecimal characters.")
        }
        val authoredAt = commitJson.requireIsoInstant("authoredAt")
        val commit = NightlyUpdateCommit(
            sha = commitSha,
            subject = commitJson.requireNonBlankString("subject"),
            body = commitJson.optionalString("body"),
            authorName = commitJson.requireNonBlankString("authorName"),
            authoredAt = authoredAt,
        )

        val apkJson = root.requireObject("apk")
        val apkName = apkJson.requireNonBlankString("name")
        if (apkName.length > MAX_ASSET_NAME_LENGTH ||
            !apkName.endsWith(".apk", ignoreCase = true) ||
            apkName.any { it == '/' || it == '\\' || it.isISOControl() }
        ) {
            throw UpdateManifestValidationException("Nightly update asset name is invalid.")
        }
        val downloadUrl = apkJson.requireNonBlankString("downloadUrl")
        val builtAtUtc = root.requireIsoInstant("builtAtUtc")
        validateRelease(downloadUrl, apkName, commitSha, builtAtUtc, root.optionalString("releaseTag"))
        val sizeBytes = apkJson.requirePositiveLong("sizeBytes")
        if (sizeBytes > MAX_UPDATE_APK_BYTES) {
            throw UpdateManifestValidationException("APK size exceeds the download limit.")
        }
        val sha256 = apkJson.requireNonBlankString("sha256").lowercase()
        if (!SHA256_REGEX.matches(sha256)) {
            throw UpdateManifestValidationException("APK SHA-256 is invalid.")
        }

        return NightlyUpdateManifest(
            schemaVersion = schemaVersion,
            channel = channel,
            branch = branch,
            versionName = root.requireNonBlankString("versionName"),
            versionCode = root.requirePositiveInt("versionCode"),
            commit = commit,
            builtAtUtc = builtAtUtc,
            apk = preferArchive(
                root,
                NightlyUpdateApk(apkName, downloadUrl, sizeBytes, sha256),
                commitSha,
                builtAtUtc,
            ),
        )
    }

    private fun validateRelease(url: String, name: String, sha: String, timestamp: String, declaredTag: String = ""): String {
        try {
            val tag = NightlyReleasePaths.tagFor(url, name)
            NightlyReleasePaths.validateBuild(tag, sha, timestamp)
            require(declaredTag.isEmpty() || declaredTag == tag) { "Release tag differs from APK URL" }
            return tag
        } catch (failure: Exception) {
            throw UpdateManifestValidationException(failure.message ?: "Invalid Nightly release URL")
        }
    }

    private fun preferArchive(root: JSONObject, alias: NightlyUpdateApk, sha: String, timestamp: String): NightlyUpdateApk {
        if (!root.has("archive")) return alias
        val archive = root.requireObject("archive")
        val tag = archive.requireNonBlankString("tag")
        if (!NightlyReleasePaths.isVersionedTag(tag)) {
            throw UpdateManifestValidationException("Archive must use a per-build Nightly tag")
        }
        val apk = archive.requireObject("apk")
        val name = apk.requireNonBlankString("name")
        val url = apk.requireNonBlankString("downloadUrl")
        validateRelease(url, name, sha, timestamp, tag)
        if (name != alias.name || apk.requirePositiveLong("sizeBytes") != alias.sizeBytes ||
            apk.requireNonBlankString("sha256").lowercase() != alias.sha256
        ) {
            throw UpdateManifestValidationException("Archived APK metadata differs from the channel APK")
        }
        return alias.copy(downloadUrl = url)
    }

    private companion object {
        private const val SUPPORTED_SCHEMA_VERSION = 1
        private const val EXPECTED_CHANNEL = "nightly"
        private val EXPECTED_BRANCHES = setOf("main", "master")
        private const val MAX_ASSET_NAME_LENGTH = 255
        private val FULL_SHA_REGEX = Regex("^[0-9a-f]{40}$")
        private val SHA256_REGEX = Regex("^[0-9a-f]{64}$")
    }
}

private fun JSONObject.requireObject(name: String): JSONObject {
    return optJSONObject(name)
        ?: throw UpdateManifestValidationException("Missing update manifest object: $name")
}

private fun JSONObject.requireNonBlankString(name: String): String {
    val rawValue = opt(name)
    if (rawValue !is String) {
        throw UpdateManifestValidationException("Update manifest value must be a string: $name")
    }
    val value = rawValue.trim()
    if (value.isBlank()) {
        throw UpdateManifestValidationException("Missing update manifest string: $name")
    }
    return value
}

private fun JSONObject.optionalString(name: String): String {
    if (!has(name) || isNull(name)) {
        return ""
    }
    return opt(name) as? String
        ?: throw UpdateManifestValidationException("Update manifest value must be a string: $name")
}

private fun JSONObject.requirePositiveInt(name: String): Int {
    val rawValue = opt(name)
    val value = if (rawValue is Int) {
        rawValue
    } else if (rawValue is Long) {
        rawValue.takeIf { it in 1..Int.MAX_VALUE }?.toInt() ?: -1
    } else {
        -1
    }
    if (value <= 0) {
        throw UpdateManifestValidationException("Update manifest value must be positive: $name")
    }
    return value
}

private fun JSONObject.requirePositiveLong(name: String): Long {
    val rawValue = opt(name)
    val value = if (rawValue is Int) {
        rawValue.toLong()
    } else if (rawValue is Long) {
        rawValue
    } else {
        -1L
    }
    if (value <= 0L) {
        throw UpdateManifestValidationException("Update manifest value must be positive: $name")
    }
    return value
}

private fun JSONObject.requireIsoInstant(name: String): String {
    val value = requireNonBlankString(name)
    runCatching { Instant.parse(value) }
        .getOrElse { throw UpdateManifestValidationException("Update manifest timestamp is invalid: $name") }
    return value
}
