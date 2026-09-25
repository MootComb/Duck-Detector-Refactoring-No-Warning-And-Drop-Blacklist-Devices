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

package com.eltavine.duckdetector.core.ui

import androidx.compose.runtime.Immutable
import androidx.compose.runtime.ProvidableCompositionLocal
import androidx.compose.runtime.staticCompositionLocalOf

/**
 * Build metadata of the running application.
 *
 * Only the application module owns `BuildConfig`, so libraries receive these values from the
 * composition root instead of reading a generated class they cannot see.
 */
@Immutable
public data class AppBuildInfo(
    public val versionName: String,
    public val versionCode: Int,
    public val buildHash: String,
    public val buildTimeUtc: String,
    public val isAlphaVersion: Boolean,
)

public val LocalAppBuildInfo: ProvidableCompositionLocal<AppBuildInfo> =
    staticCompositionLocalOf { error("AppBuildInfo must be provided by the application composition root") }
