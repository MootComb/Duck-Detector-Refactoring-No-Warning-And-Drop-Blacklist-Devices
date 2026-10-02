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

package com.eltavine.duckdetector.features.update.presentation

import com.eltavine.duckdetector.features.update.domain.GitHubAcceleration
import java.util.Locale

/**
 * The offer goes to users who read the app in Chinese, in any script or region, and have not chosen
 * yet. The language only hints at a network where GitHub is hard to reach, so the user is asked
 * rather than switched over.
 */
fun shouldOfferGitHubAcceleration(acceleration: GitHubAcceleration, appLocale: Locale): Boolean =
    acceleration == GitHubAcceleration.UNDECIDED && appLocale.language == Locale.CHINESE.language
