/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.eltavine.duckdetector.features.update.data

import java.net.URI
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset

/** Owns the official repository and immutable Nightly tag/asset contract. */
internal object NightlyReleasePaths {
    const val REPOSITORY = "https://github.com/eltavine/Duck-Detector-Refactoring"
    private const val DOWNLOAD_PATH = "/eltavine/Duck-Detector-Refactoring/releases/download/"
    private val tagPattern = Regex("""nightly-(\d{4}-\d{2}-\d{2})-([0-9a-f]{8})""")

    fun isVersionedTag(tag: String): Boolean {
        val match = tagPattern.matchEntire(tag) ?: return false
        return runCatching { LocalDate.parse(match.groupValues[1]) }.isSuccess
    }

    fun manifestUrl(tag: String): String {
        require(tag == "nightly" || isVersionedTag(tag)) { "Invalid Nightly release tag" }
        return "$REPOSITORY/releases/download/$tag/update.json"
    }

    fun tagFor(url: String, name: String): String {
        val uri = URI(url)
        require(uri.scheme == "https" && uri.host.equals("github.com", ignoreCase = true) &&
            uri.rawUserInfo == null && uri.port == -1 && uri.rawQuery == null && uri.rawFragment == null
        ) { "APK URL must use the official GitHub host" }
        val suffix = uri.path.removePrefix(DOWNLOAD_PATH)
        val tag = suffix.substringBefore('/')
        require(uri.path == "$DOWNLOAD_PATH$tag/$name") { "APK URL is outside the repository" }
        manifestUrl(tag)
        return tag
    }

    fun validateBuild(tag: String, sha: String, timestamp: String) {
        // The mutable compatibility channel predates the per-build naming contract.
        if (tag == "nightly") return
        val match = requireNotNull(tagPattern.matchEntire(tag))
        val date = Instant.parse(timestamp).atOffset(ZoneOffset.UTC).toLocalDate().toString()
        require(match.groupValues[1] == date && sha.startsWith(match.groupValues[2])) {
            "Nightly tag does not match the manifest's build date and commit"
        }
    }
}
