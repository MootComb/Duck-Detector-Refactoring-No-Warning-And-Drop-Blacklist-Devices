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

package com.eltavine.duckdetector.features.update.domain

data class NightlyUpdateManifest(
    val schemaVersion: Int,
    val channel: String,
    val branch: String,
    val versionName: String,
    val versionCode: Int,
    val commit: NightlyUpdateCommit,
    val builtAtUtc: String,
    val apk: NightlyUpdateApk,
)

data class NightlyUpdateCommit(
    val sha: String,
    val subject: String,
    val body: String,
    val authorName: String,
    val authoredAt: String,
)

data class NightlyUpdateApk(
    val name: String,
    val downloadUrl: String,
    val sizeBytes: Long,
    val sha256: String,
)

data class UpdateChangelogEntry(
    val sha: String,
    val subject: String,
    val authorName: String,
)

data class AvailableNightlyUpdate(
    val manifest: NightlyUpdateManifest,
    val changelog: List<UpdateChangelogEntry>,
    /** Null when GitHub could not compare the builds, so [changelog] holds only the newest commit. */
    val remainingCommitCount: Int?,
    /** The manifest's GitHub download URL, or that URL through gh-proxy.com while acceleration is on. */
    val downloadUrl: String,
    val compareUrl: String,
)

sealed interface UpdateCheckResult {
    data class Current(
        val manifest: NightlyUpdateManifest,
    ) : UpdateCheckResult

    data class Available(
        val update: AvailableNightlyUpdate,
    ) : UpdateCheckResult
}
