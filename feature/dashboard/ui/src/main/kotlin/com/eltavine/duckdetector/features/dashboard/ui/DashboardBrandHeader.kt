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

package com.eltavine.duckdetector.features.dashboard.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Badge
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.ContinuousCornerShape
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.ui.LocalAppBuildInfo
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.openExternalUri
import com.eltavine.duckdetector.core.ui.presentation.formatBuildTimeUtc
import com.eltavine.duckdetector.core.ui.R as CoreUiR

// An app icon's corner is close to a quarter of its side.
private val AppIconShape = ContinuousCornerShape(14.dp)

/** The page's large title, under the app icon, with the build it describes. */
@Composable
internal fun BrandHeader() {
    val context = LocalContext.current
    val buildInfo = LocalAppBuildInfo.current
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 4.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            AppIcon()
            Spacer(modifier = Modifier.weight(1f))
            FilledIconButton(
                onClick = { openExternalUri(context, "https://t.me/duck_detector") },
                colors = IconButtonDefaults.filledIconButtonColors(
                    containerColor = DuckTheme.palette.groupedSurface,
                    contentColor = MaterialTheme.colorScheme.primary,
                ),
            ) {
                Icon(
                    painter = painterResource(CoreUiR.drawable.ic_telegram),
                    contentDescription = stringResource(CoreUiR.string.social_telegram),
                    modifier = Modifier.size(20.dp),
                )
            }
        }
        WrapSafeText(
            text = stringResource(CoreUiR.string.app_name),
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 12.dp)
                .semantics { heading() },
            style = DuckTypography.LargeTitle,
            color = MaterialTheme.colorScheme.onSurface,
        )
        BrandMetaLine(
            icon = Icons.Rounded.Badge,
            text = "${buildInfo.versionName}(${buildInfo.versionCode})",
        )
        BrandMetaLine(
            icon = Icons.Rounded.Schedule,
            text = "Build Time (UTC)  ${formatBuildTimeUtc(buildInfo.buildTimeUtc)}",
        )
    }
}

// The logo is a one-color glyph tinted with the text color, so it inverts with the theme: black on
// the light tile, white on the dark one.
@Composable
private fun AppIcon() {
    Box(
        modifier = Modifier
            .size(56.dp)
            .background(color = DuckTheme.palette.groupedSurface, shape = AppIconShape),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            painter = painterResource(R.drawable.ic_duck_logo),
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.size(34.dp),
        )
    }
}

@Composable
private fun BrandMetaLine(
    icon: ImageVector,
    text: String,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(14.dp),
        )
        WrapSafeText(
            text = text,
            style = DuckTypography.Footnote,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}