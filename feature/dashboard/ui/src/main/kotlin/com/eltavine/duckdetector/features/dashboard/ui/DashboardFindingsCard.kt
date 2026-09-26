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

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import com.eltavine.duckdetector.core.ui.theme.ShapeTokens
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardFindingModel

@Composable
internal fun DashboardFindingsCard(
    findings: List<DashboardFindingModel>,
) {
    Surface(
        shape = ShapeTokens.CornerExtraLargeIncreased,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 18.dp, vertical = 18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            DashboardFindingsHeader(findings = findings)
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                findings.forEach { finding ->
                    DashboardFindingRow(finding = finding)
                }
            }
        }
    }
}

@Composable
private fun DashboardFindingsHeader(
    findings: List<DashboardFindingModel>,
) {
    val headerStatus = findings.firstOrNull()?.status
        ?: com.eltavine.duckdetector.core.evidence.DetectorStatus.allClear()
    val appearance = rememberStatusAppearance(headerStatus)
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Surface(
            shape = ShapeTokens.CornerLargeIncreased,
            color = MaterialTheme.colorScheme.surfaceContainerHigh,
        ) {
            Box(
                modifier = Modifier
                    .size(42.dp)
                    .padding(10.dp),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = appearance.icon,
                    contentDescription = null,
                    tint = appearance.iconTint,
                )
            }
        }
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            WrapSafeText(
                text = "Top findings",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
            WrapSafeText(
                text = "Priority review queue",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Surface(
            shape = ShapeTokens.CornerLarge,
            color = MaterialTheme.colorScheme.surfaceContainerHigh,
        ) {
            WrapSafeText(
                text = findings.size.toString(),
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 9.dp),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}

@Composable
private fun DashboardFindingRow(
    finding: DashboardFindingModel,
) {
    val appearance = rememberStatusAppearance(finding.status)
    Surface(
        shape = ShapeTokens.CornerLargeIncreased,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Row(
                    modifier = Modifier.weight(1f),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Surface(
                        shape = CircleShape,
                        color = appearance.iconTint.copy(alpha = 0.14f),
                    ) {
                        Box(
                            modifier = Modifier
                                .size(30.dp)
                                .padding(7.dp),
                            contentAlignment = Alignment.Center,
                        ) {
                            Icon(
                                imageVector = appearance.icon,
                                contentDescription = null,
                                tint = appearance.iconTint,
                                modifier = Modifier.size(16.dp),
                            )
                        }
                    }
                    WrapSafeText(
                        text = finding.detectorTitle,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Surface(
                    shape = ShapeTokens.CornerLarge,
                    color = MaterialTheme.colorScheme.surfaceContainerHighest,
                ) {
                    WrapSafeText(
                        text = findingSeverityLabel(finding),
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 7.dp),
                        style = MaterialTheme.typography.labelSmall,
                        color = appearance.iconTint,
                    )
                }
            }
            WrapSafeText(
                text = finding.headline,
                modifier = Modifier.fillMaxWidth(),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.42f),
                thickness = 1.dp,
            )
            WrapSafeText(
                text = finding.detail,
                modifier = Modifier.fillMaxWidth(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

private fun findingSeverityLabel(
    finding: DashboardFindingModel,
): String {
    return when (finding.status.severity) {
        DetectionSeverity.DANGER -> "High"
        DetectionSeverity.WARNING -> "Warn"
        DetectionSeverity.INFO -> "Check"
        DetectionSeverity.ALL_CLEAR -> "Clear"
    }
}
