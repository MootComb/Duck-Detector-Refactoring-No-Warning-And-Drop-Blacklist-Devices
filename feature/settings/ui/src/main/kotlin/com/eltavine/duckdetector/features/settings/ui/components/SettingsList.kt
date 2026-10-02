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

package com.eltavine.duckdetector.features.settings.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItemColors
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.ListItemShapes
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedListItem
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import com.eltavine.duckdetector.core.ui.components.WrapSafeText

/** Horizontal inset of row content, which section titles and footnotes align with. */
private val SettingsItemInset = 18.dp

private val SettingsItemPadding = PaddingValues(horizontal = SettingsItemInset, vertical = 14.dp)

@Composable
internal fun SettingsSection(
    title: String,
    modifier: Modifier = Modifier,
    badge: String? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = SettingsItemInset),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            WrapSafeText(
                text = title,
                modifier = Modifier.semantics { heading() },
                style = DuckTypography.FootnoteEmphasized,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (badge != null) {
                WrapSafeText(
                    text = badge,
                    modifier = Modifier
                        .background(color = DuckTheme.palette.groupedSurface, shape = ShapeTokens.CornerFull)
                        .padding(horizontal = 8.dp, vertical = 1.dp),
                    style = DuckTypography.Caption.copy(fontFeatureSettings = "tnum"),
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }
        }
        content()
    }
}

/** Rows that read as one block: separated by the segmented gap and shaped by [settingsItemShapes]. */
@Composable
internal fun SettingsGroup(content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(ListItemDefaults.SegmentedGap),
        content = content,
    )
}

@Composable
internal fun SettingsItem(
    headline: String,
    shapes: ListItemShapes,
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
    enabled: Boolean = true,
    colors: ListItemColors = settingsItemColors(),
    leadingContent: (@Composable () -> Unit)? = null,
    supportingContent: (@Composable () -> Unit)? = null,
    trailingContent: (@Composable () -> Unit)? = null,
) {
    val headlineContent: @Composable () -> Unit = {
        WrapSafeText(text = headline, style = DuckTypography.Body)
    }
    if (onClick == null) {
        SegmentedListItem(
            shapes = shapes,
            modifier = modifier,
            enabled = enabled,
            leadingContent = leadingContent,
            trailingContent = trailingContent,
            supportingContent = supportingContent,
            colors = colors,
            contentPadding = SettingsItemPadding,
            content = headlineContent,
        )
    } else {
        SegmentedListItem(
            onClick = onClick,
            shapes = shapes,
            modifier = modifier,
            enabled = enabled,
            leadingContent = leadingContent,
            trailingContent = trailingContent,
            supportingContent = supportingContent,
            colors = colors,
            contentPadding = SettingsItemPadding,
            content = headlineContent,
        )
    }
}

/** Disabled rows keep their colors: a row is disabled only while it is busy, not unavailable. */
@Composable
internal fun settingsItemColors(
    containerColor: Color = DuckTheme.palette.groupedSurface,
    contentColor: Color = MaterialTheme.colorScheme.onSurface,
    supportingColor: Color = MaterialTheme.colorScheme.onSurfaceVariant,
): ListItemColors = ListItemDefaults.segmentedColors(
    containerColor = containerColor,
    contentColor = contentColor,
    leadingContentColor = contentColor,
    trailingContentColor = supportingColor,
    supportingContentColor = supportingColor,
    disabledContainerColor = containerColor,
    disabledContentColor = contentColor,
    disabledLeadingContentColor = contentColor,
    disabledTrailingContentColor = supportingColor,
    disabledSupportingContentColor = supportingColor,
)

@Composable
internal fun SettingsIconTile(
    icon: ImageVector,
    tint: Color = MaterialTheme.colorScheme.primary,
) {
    SettingsIconTile {
        Icon(imageVector = icon, contentDescription = null, tint = tint)
    }
}

@Composable
internal fun SettingsIconTile(
    containerColor: Color = DuckTheme.palette.groupedInset,
    content: @Composable BoxScope.() -> Unit,
) {
    Box(
        modifier = Modifier
            .size(40.dp)
            .background(color = containerColor, shape = ShapeTokens.CornerMedium),
        contentAlignment = Alignment.Center,
        content = content,
    )
}

@Composable
internal fun SettingsFootnote(
    text: String,
    modifier: Modifier = Modifier,
    title: String? = null,
    icon: ImageVector? = null,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = SettingsItemInset),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        if (icon != null) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier
                    .padding(top = 1.dp)
                    .size(18.dp),
            )
        }
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            if (title != null) {
                WrapSafeText(
                    text = title,
                    style = DuckTypography.FootnoteEmphasized,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            WrapSafeText(
                text = text,
                style = DuckTypography.Footnote,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
