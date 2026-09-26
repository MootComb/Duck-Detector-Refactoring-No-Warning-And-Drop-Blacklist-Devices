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

package com.eltavine.duckdetector.buildlogic.assets

import java.io.File
import org.json.JSONArray
import org.json.JSONException

internal const val GITHUB_CONTRIBUTORS_AVATAR_DIRECTORY = "github_contributors/avatars"

/** One contributor as the app's contributors asset records it. */
internal data class ContributorRecord(
    val login: String,
    val name: String,
    val profileUrl: String,
    val avatarUrl: String?,
    val avatarFileName: String,
    val avatarAssetPath: String,
    val contributions: Int,
    val codeVolume: Int,
    val summaryKey: String?,
    val contributionKeys: List<String>,
)

/** The summary and contribution keys a contributor already has in the committed asset. */
internal data class ContributorMetadata(
    val summaryKey: String?,
    val contributionKeys: List<String>,
)

/**
 * The records to publish: the manual contributors, then GitHub's with the keys [recorded] for them,
 * in contribution order.
 */
internal fun contributorRecords(
    remote: List<GitHubContributor>,
    recorded: Map<String, ContributorMetadata>,
): List<ContributorRecord> {
    // Manual contributors precede remote records so distinctBy keeps the local entry if
    // GitHub later returns the same login. The merged list is then sorted by the normal
    // contribution/card order instead of being appended ad hoc.
    // 手动贡献者放在远端记录之前，使 distinctBy 在 GitHub 之后返回同一 login 时保留本地
    // 条目；合并后的列表仍按正常贡献量与卡片顺序排序，而不是临时追加。
    val local = LOCAL_CONTRIBUTORS.map { contributor ->
        ContributorRecord(
            login = contributor.login,
            name = contributor.name,
            profileUrl = contributor.profileUrl,
            avatarUrl = null,
            avatarFileName = contributor.avatarFileName,
            avatarAssetPath = contributor.avatarAssetPath,
            contributions = contributor.contributions,
            codeVolume = 0,
            summaryKey = contributor.summaryKey,
            contributionKeys = contributor.contributionKeys,
        )
    }
    val fetched = remote.map { contributor ->
        val assetFileName = sanitizeAssetFileName(contributor.login) + ".jpg"
        val metadata = recorded[contributor.login]
        ContributorRecord(
            login = contributor.login,
            name = contributor.name,
            profileUrl = contributor.profileUrl,
            avatarUrl = contributor.avatarUrl,
            avatarFileName = assetFileName,
            avatarAssetPath = "$GITHUB_CONTRIBUTORS_AVATAR_DIRECTORY/$assetFileName",
            contributions = contributor.contributions,
            codeVolume = contributor.codeVolume,
            summaryKey = metadata?.summaryKey,
            contributionKeys = metadata?.contributionKeys ?: emptyList(),
        )
    }
    return (local + fetched)
        .distinctBy { it.login }
        .sortedWith(
            compareByDescending<ContributorRecord> { it.contributions }
                .thenByDescending { it.codeVolume }
                .thenBy { it.login.lowercase() },
        )
}

/** The keys recorded per login in an existing contributors asset; empty when there is none to read. */
internal fun readRecordedMetadata(file: File): Map<String, ContributorMetadata> {
    if (!file.isFile) {
        return emptyMap()
    }
    val array = try {
        JSONArray(file.readText(Charsets.UTF_8))
    } catch (_: JSONException) {
        return emptyMap()
    }
    return buildMap {
        for (index in 0 until array.length()) {
            val item = array.optJSONObject(index) ?: continue
            val login = item.optString("login").trim()
            if (login.isBlank()) {
                continue
            }
            put(
                login,
                ContributorMetadata(
                    summaryKey = item.optString("summaryKey").trim().ifBlank { null },
                    contributionKeys = item.optJSONArray("contributionKeys").toStringList(),
                )
            )
        }
    }
}

private data class LocalContributor(
    val login: String,
    val name: String,
    val profileUrl: String,
    val avatarFileName: String,
    val avatarAssetPath: String,
    val contributions: Int,
    val summaryKey: String,
    val contributionKeys: List<String>,
)

private val LOCAL_CONTRIBUTORS = listOf(
    LocalContributor(
        login = "SakanyaNotBot",
        name = "无影",
        profileUrl = "https://github.com/SakanyaNotBot",
        avatarFileName = "sakanyanotbot.jpg",
        avatarAssetPath = "github_contributors/avatars/sakanyanotbot.jpg",
        contributions = 1,
        summaryKey = "author_summary_wuying",
        contributionKeys = listOf("security"),
    ),
)

private fun sanitizeAssetFileName(login: String): String {
    return buildString(login.length) {
        login.forEach { character ->
            append(
                when {
                    character.isLetterOrDigit() -> character.lowercaseChar()
                    character == '-' || character == '_' -> character
                    else -> '_'
                }
            )
        }
    }
}

private fun JSONArray?.toStringList(): List<String> {
    if (this == null) {
        return emptyList()
    }
    return buildList(length()) {
        for (index in 0 until length()) {
            val value = optString(index).trim()
            if (value.isNotEmpty()) {
                add(value)
            }
        }
    }
}
