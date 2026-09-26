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

package com.eltavine.duckdetector.features.settings.ui.components

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import com.eltavine.duckdetector.features.settings.ui.R
import compose.icons.SimpleIcons
import compose.icons.simpleicons.Assemblyscript
import compose.icons.simpleicons.Cplusplus
import compose.icons.simpleicons.Figma
import compose.icons.simpleicons.Kotlin
import org.json.JSONArray

internal data class AuthorProfile(
    val login: String,
    val name: String,
    val profileUrl: String,
    val avatarAssetPath: String?,
    val contributionSummary: String,
    val contributions: List<AuthorContribution>,
)

internal data class ContributorSnapshot(
    val login: String,
    val name: String,
    val profileUrl: String,
    val avatarAssetPath: String?,
    val summaryKey: String?,
    val contributionKeys: List<String>,
)

internal sealed class AuthorContribution(
    val label: String,
    val icon: ImageVector,
    val tint: Color,
) {
    data object Ui : AuthorContribution(
        label = "UI",
        icon = SimpleIcons.Figma,
        tint = Color(0xFFF24E1E),
    )

    data object Cpp : AuthorContribution(
        label = "C++",
        icon = SimpleIcons.Cplusplus,
        tint = Color(0xFF00599C),
    )

    data object Asm : AuthorContribution(
        label = "ASM",
        icon = SimpleIcons.Assemblyscript,
        tint = Color(0xFF007AAC),
    )

    data object Kotlin : AuthorContribution(
        label = "Kotlin",
        icon = SimpleIcons.Kotlin,
        tint = Color(0xFF7F52FF),
    )

    data object Security : AuthorContribution(
        label = "Security",
        icon = Icons.Rounded.BugReport,
        tint = Color(0xFFD32F2F),
    )
}

internal fun loadContributorSnapshots(context: android.content.Context): List<ContributorSnapshot> {
    val assetManager = context.assets
    val payload = runCatching {
        assetManager.open(CONTRIBUTORS_ASSET_FILE_NAME).bufferedReader(Charsets.UTF_8).use { reader ->
            reader.readText()
        }
    }.getOrNull() ?: return emptyList()
    return runCatching {
        val array = JSONArray(payload)
        buildList(array.length()) {
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                val login = item.optString("login").trim()
                val name = item.optString("name").trim().ifBlank { login }
                if (login.isBlank()) {
                    continue
                }
                add(
                    ContributorSnapshot(
                        login = login,
                        name = name,
                        profileUrl = item.optString("profileUrl").trim().ifBlank { "https://github.com/$login" },
                        avatarAssetPath = item.optString("avatarAssetPath").trim().ifBlank { null },
                        summaryKey = item.optString("summaryKey").trim().ifBlank { null },
                        contributionKeys = item.optJSONArray("contributionKeys").toStringList(),
                    )
                )
            }
        }
    }.getOrDefault(emptyList())
}

internal fun summaryResIdForKey(summaryKey: String?): Int {
    return when (summaryKey) {
        "author_summary_eltavine" -> R.string.author_summary_eltavine
        "author_summary_baka" -> R.string.author_summary_baka
        "author_summary_xiaotong" -> R.string.author_summary_xiaotong
        "author_summary_searchur" -> R.string.author_summary_searchur
        "author_summary_wxx" -> R.string.author_summary_wxx
        "author_summary_alex" -> R.string.author_summary_alex
        "author_summary_hsskyboy" -> R.string.author_summary_hsskyboy
        "author_summary_lingqing" -> R.string.author_summary_lingqing
        "author_summary_qwq233" -> R.string.author_summary_qwq233
        "author_summary_sqmy" -> R.string.author_summary_sqmy
        "author_summary_victor" -> R.string.author_summary_victor
        "author_summary_zg089" -> R.string.author_summary_zg089
        "author_summary_coolzyd" -> R.string.author_summary_coolzyd
        "author_summary_947409161" -> R.string.author_summary_947409161
        "author_summary_mirin" -> R.string.author_summary_mirin
        "author_summary_aviraxp" -> R.string.author_summary_aviraxp
        "author_summary_5ec1cff" -> R.string.author_summary_5ec1cff
        "author_summary_wuying" -> R.string.author_summary_wuying
        else -> R.string.author_summary_default
    }
}

internal fun authorContributionForKey(key: String): AuthorContribution? {
    return when (key.lowercase()) {
        "ui" -> AuthorContribution.Ui
        "cpp" -> AuthorContribution.Cpp
        "asm" -> AuthorContribution.Asm
        "kotlin" -> AuthorContribution.Kotlin
        "security" -> AuthorContribution.Security
        else -> null
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

private const val CONTRIBUTORS_ASSET_FILE_NAME = "github_contributors.json"
