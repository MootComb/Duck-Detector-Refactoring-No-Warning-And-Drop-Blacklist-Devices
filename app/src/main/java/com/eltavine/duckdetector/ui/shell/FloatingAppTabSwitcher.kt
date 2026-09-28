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

package com.eltavine.duckdetector.ui.shell

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.selectable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Home
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens

/** A floating capsule over the page: translucent enough to let the content below show through. */
@Composable
fun FloatingAppTabSwitcher(
    selectedDestination: AppDestination,
    onSelectDestination: (AppDestination) -> Unit,
    modifier: Modifier = Modifier,
) {
    val palette = DuckTheme.palette
    Surface(
        modifier = modifier,
        shape = ShapeTokens.CornerFull,
        color = palette.groupedSurface.copy(alpha = 0.9f),
        border = BorderStroke(Dp.Hairline, palette.separator),
        shadowElevation = 10.dp,
    ) {
        Row(
            modifier = Modifier.padding(6.dp),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            AppDestination.entries.forEach { destination ->
                val selected = destination == selectedDestination
                val accent = MaterialTheme.colorScheme.primary
                val background by animateColorAsState(
                    targetValue = if (selected) accent.copy(alpha = 0.14f) else Color.Transparent,
                    label = "tabBackground",
                )
                val tint by animateColorAsState(
                    targetValue = if (selected) accent else MaterialTheme.colorScheme.onSurfaceVariant,
                    label = "tabTint",
                )
                Box(
                    modifier = Modifier
                        .clip(ShapeTokens.CornerFull)
                        .background(background)
                        .selectable(
                            selected = selected,
                            role = Role.Tab,
                            onClick = { onSelectDestination(destination) },
                        )
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = iconFor(destination),
                        contentDescription = destination.name,
                        tint = tint,
                        modifier = Modifier.size(24.dp),
                    )
                }
            }
        }
    }
}

private fun iconFor(destination: AppDestination): ImageVector {
    return when (destination) {
        AppDestination.MAIN -> Icons.Rounded.Home
        AppDestination.SETTINGS -> Icons.Rounded.Settings
    }
}
