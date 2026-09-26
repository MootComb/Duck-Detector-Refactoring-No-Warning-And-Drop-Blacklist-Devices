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

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.components.ContextLine
import com.eltavine.duckdetector.core.ui.components.DetectorCardFrame
import com.eltavine.duckdetector.core.ui.components.DetectorSectionFrame
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.model.ContextItemModel
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import com.eltavine.duckdetector.core.ui.theme.ShapeTokens
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsCardModel
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsHeaderFact
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsHeaderFactModel
import com.eltavine.duckdetector.features.dangerousapps.ui.DangerousAppsTargetsDialog

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun DangerousAppsDetectorCard(
    model: DangerousAppsCardModel,
    modifier: Modifier = Modifier,
) {
    var showTargetsDialog by rememberSaveable { mutableStateOf(false) }

    if (showTargetsDialog) {
        DangerousAppsTargetsDialog(
            targets = model.targetApps,
            onDismiss = { showTargetsDialog = false },
        )
    }

    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.Apps,
        modifier = modifier,
        headerFacts = {
            DangerousAppsOverview(model = model)
        },
        footerActions = {
            OutlinedButton(
                onClick = { showTargetsDialog = true },
            ) {
                Icon(
                    imageVector = Icons.Rounded.Apps,
                    contentDescription = null,
                )
                WrapSafeText(
                    text = "View target apps (${model.targetApps.size})",
                    modifier = Modifier.padding(start = 8.dp),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }
        },
    ) {
        model.hmaAlert?.let { hmaAlert ->
            DangerousAppsHmaSection(
                alert = hmaAlert,
            )
        }

        DetectorSectionFrame(
            title = "Packages",
            icon = Icons.Rounded.Shield,
        ) {
            DangerousAppsPackageSection(model = model)
        }

        DetectorSectionFrame(
            title = "Context",
            icon = Icons.Rounded.Search,
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                model.context.forEach { contextItem ->
                    ContextLine(item = ContextItemModel(label = contextItem.label, value = contextItem.value))
                }
            }
        }
    }
}

@Composable
private fun DangerousAppsOverview(
    model: DangerousAppsCardModel,
) {
    val targets = model.headerFacts.firstOrNull { it.fact == DangerousAppsHeaderFact.TARGETS } ?: return
    val packageManager = model.headerFacts.firstOrNull { it.fact == DangerousAppsHeaderFact.PM } ?: return
    val hits = model.headerFacts.firstOrNull { it.fact == DangerousAppsHeaderFact.HITS } ?: return
    val hidden = model.headerFacts.firstOrNull { it.fact == DangerousAppsHeaderFact.HIDDEN } ?: return

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        DangerousAppsFactPairCard(
            primary = targets,
            secondary = packageManager,
            modifier = Modifier.weight(1f),
        )
        DangerousAppsFactPairCard(
            primary = hits,
            secondary = hidden,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun DangerousAppsFactPairCard(
    primary: DangerousAppsHeaderFactModel,
    secondary: DangerousAppsHeaderFactModel,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = ShapeTokens.CornerExtraLarge,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            DangerousAppsFactPairRow(fact = primary)
            HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.32f),
                thickness = 1.dp,
            )
            DangerousAppsFactPairRow(fact = secondary)
        }
    }
}

@Composable
private fun DangerousAppsFactPairRow(
    fact: DangerousAppsHeaderFactModel,
) {
    val appearance = rememberStatusAppearance(fact.status)
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Icon(
                imageVector = appearance.icon,
                contentDescription = null,
                tint = appearance.iconTint,
                modifier = Modifier.size(15.dp),
            )
            WrapSafeText(
                text = fact.label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        WrapSafeText(
            text = fact.value,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}
