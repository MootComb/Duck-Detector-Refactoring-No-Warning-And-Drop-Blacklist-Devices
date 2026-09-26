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
import org.json.JSONObject

/**
 * Writes [contributors] to [contributorsFile], downloads the avatar of each one with a remote avatar
 * into [avatarDirectory], and deletes the avatars no contributor names any more.
 */
internal fun writeContributorsAsset(
    contributors: List<ContributorRecord>,
    contributorsFile: File,
    avatarDirectory: File,
    downloadAvatar: (url: String) -> ByteArray,
) {
    val payload = JSONArray()
    val expectedAvatarFiles = linkedSetOf<String>()

    contributors.forEach { contributor ->
        expectedAvatarFiles += contributor.avatarFileName
        contributor.avatarUrl?.let { avatarUrl ->
            avatarDirectory.resolve(contributor.avatarFileName).writeBytes(downloadAvatar(avatarUrl))
        }
        payload.put(
            JSONObject()
                .put("login", contributor.login)
                .put("name", contributor.name)
                .put("profileUrl", contributor.profileUrl)
                .put("avatarAssetPath", contributor.avatarAssetPath)
                .put("contributions", contributor.contributions)
                .put("summaryKey", contributor.summaryKey)
                .put("contributionKeys", JSONArray(contributor.contributionKeys))
        )
    }

    avatarDirectory.listFiles().orEmpty()
        .filter { it.isFile && it.name !in expectedAvatarFiles }
        .forEach { it.delete() }

    contributorsFile.writeText(payload.toString(2), Charsets.UTF_8)
}
