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

package com.eltavine.duckdetector.features.update.presentation

import com.eltavine.duckdetector.features.update.domain.GitHubAcceleration
import java.util.Locale
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GitHubAccelerationOfferTest {

    @Test
    fun `undecided users reading Chinese are asked in every script and region`() {
        listOf("zh-CN", "zh-TW", "zh-Hant-HK", "zh-SG", "zh").forEach { tag ->
            assertTrue(
                tag,
                shouldOfferGitHubAcceleration(GitHubAcceleration.UNDECIDED, Locale.forLanguageTag(tag)),
            )
        }
    }

    @Test
    fun `undecided users reading another language are not asked`() {
        listOf("en-US", "ja-JP", "ko-KR", "vi-VN").forEach { tag ->
            assertFalse(
                tag,
                shouldOfferGitHubAcceleration(GitHubAcceleration.UNDECIDED, Locale.forLanguageTag(tag)),
            )
        }
    }

    @Test
    fun `a recorded choice is not asked again`() {
        val chinese = Locale.forLanguageTag("zh-CN")

        assertFalse(shouldOfferGitHubAcceleration(GitHubAcceleration.ENABLED, chinese))
        assertFalse(shouldOfferGitHubAcceleration(GitHubAcceleration.DISABLED, chinese))
    }
}
