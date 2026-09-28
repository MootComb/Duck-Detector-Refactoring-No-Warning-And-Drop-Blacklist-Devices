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
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Timer
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.VerticalDivider
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import com.eltavine.duckdetector.core.ui.components.DetectorHairline
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardOverviewMetricModel
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardOverviewModel

@Composable
internal fun DashboardOverviewCard(
    model: DashboardOverviewModel,
) {
    val appearance = rememberStatusAppearance(model.status)
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                color = DuckTheme.palette.groupedSurface,
                shape = ShapeTokens.CornerExtraLargeIncreased,
            )
            .padding(horizontal = 20.dp, vertical = 20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        OverviewTitle(model = model)

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(60.dp)
                    .background(color = appearance.tintWash, shape = CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = appearance.icon,
                    contentDescription = null,
                    tint = appearance.iconTint,
                    modifier = Modifier.size(32.dp),
                )
            }
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                WrapSafeText(
                    text = model.headline,
                    modifier = Modifier.fillMaxWidth(),
                    style = DuckTypography.LargeTitle,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                WrapSafeText(
                    text = model.summary,
                    modifier = Modifier.fillMaxWidth(),
                    style = DuckTypography.Callout,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        DetectorHairline()
        OverviewMetrics(metrics = model.metrics)
    }
}

/** The title is one line, or the scan's completion time over its duration. */
@Composable
private fun OverviewTitle(model: DashboardOverviewModel) {
    val lines = model.title.lines().filter { it.isNotBlank() }
    Row(
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        if (model.showTitleIcon) {
            Icon(
                imageVector = Icons.Outlined.Timer,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier
                    .padding(top = 2.dp)
                    .size(14.dp),
            )
        }
        Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
            lines.forEach { line ->
                WrapSafeText(
                    text = line,
                    style = DuckTypography.Footnote,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun OverviewMetrics(
    metrics: List<DashboardOverviewMetricModel>,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(IntrinsicSize.Min),
    ) {
        metrics.forEachIndexed { index, metric ->
            if (index > 0) {
                VerticalDivider(
                    modifier = Modifier
                        .fillMaxHeight()
                        .padding(vertical = 4.dp),
                    thickness = Dp.Hairline,
                    color = DuckTheme.palette.separator,
                )
            }
            OverviewMetric(metric = metric, modifier = Modifier.weight(1f))
        }
    }
}

@Composable
private fun OverviewMetric(
    metric: DashboardOverviewMetricModel,
    modifier: Modifier = Modifier,
) {
    val appearance = rememberStatusAppearance(metric.status)
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        WrapSafeText(
            text = metric.value,
            style = DuckTypography.Numeral,
            color = MaterialTheme.colorScheme.onSurface,
        )
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(7.dp)
                    .background(color = appearance.iconTint, shape = CircleShape),
            )
            WrapSafeText(
                text = metric.label,
                style = DuckTypography.Caption,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
