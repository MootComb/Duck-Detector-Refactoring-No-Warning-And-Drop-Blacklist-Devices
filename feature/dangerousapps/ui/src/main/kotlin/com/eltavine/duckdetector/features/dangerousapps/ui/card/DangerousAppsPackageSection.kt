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

package com.eltavine.duckdetector.features.dangerousapps.ui.card

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import com.eltavine.duckdetector.core.ui.components.DetectorHairline
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsCardModel
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsPackageItemModel

@Composable
internal fun DangerousAppsPackageSection(
    model: DangerousAppsCardModel,
) {
    when {
        model.packageItems.isEmpty() -> {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 6.dp)
                    .background(color = DuckTheme.palette.groupedInset, shape = ShapeTokens.CornerLarge)
                    .padding(horizontal = 14.dp, vertical = 14.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                WrapSafeText(
                    text = "No package hits",
                    style = DuckTypography.CalloutEmphasized,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                WrapSafeText(
                    text = model.summary,
                    style = DuckTypography.Footnote,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        else -> {
            Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
                model.packageItems.forEachIndexed { index, item ->
                    DangerousAppsPackageRow(item = item)
                    if (index < model.packageItems.lastIndex) {
                        DetectorHairline()
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DangerousAppsPackageRow(
    item: DangerousAppsPackageItemModel,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        WrapSafeText(
            text = item.appName,
            style = DuckTypography.CalloutEmphasized,
            color = MaterialTheme.colorScheme.onSurface,
        )
        WrapSafeText(
            text = item.packageName,
            style = DuckTypography.Footnote.copy(fontFamily = FontFamily.Monospace),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        FlowRow(
            modifier = Modifier.padding(top = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            item.methods.forEach { method ->
                DangerousAppsMethodChip(label = method)
            }
        }
    }
}

@Composable
internal fun DangerousAppsMethodChip(
    label: String,
    warningTone: Boolean = false,
) {
    val critical = DuckTheme.palette.critical
    val containerColor = if (warningTone) critical.copy(alpha = 0.12f) else DuckTheme.palette.groupedInset
    val iconTint = if (warningTone) critical else MaterialTheme.colorScheme.primary

    Row(
        modifier = Modifier
            .background(color = containerColor, shape = ShapeTokens.CornerFull)
            .padding(horizontal = 10.dp, vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Icon(
            imageVector = Icons.Rounded.Search,
            contentDescription = null,
            tint = iconTint,
            modifier = Modifier.size(13.dp),
        )
        WrapSafeText(
            text = label,
            style = DuckTypography.Caption.copy(fontFamily = FontFamily.Monospace),
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}
