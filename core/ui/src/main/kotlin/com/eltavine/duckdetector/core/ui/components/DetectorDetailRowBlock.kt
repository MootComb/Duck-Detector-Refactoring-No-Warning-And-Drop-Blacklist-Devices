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

package com.eltavine.duckdetector.core.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.Constraints
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance

private val LabelValueGap = 16.dp
private val StackedGap = 2.dp

@Composable
public fun DetectorDetailRowBlock(
    label: String,
    value: String,
    status: DetectorStatus,
    modifier: Modifier = Modifier,
    // 让上层在不改版式的前提下给 value 文本附加隐藏手势或语义。
    // Lets callers attach hidden gestures or semantics to the value text without changing the row layout.
    valueModifier: Modifier = Modifier,
    detail: String? = null,
    detailMonospace: Boolean = false,
    statusIcon: ImageVector? = null,
    verticalPadding: Dp = 12.dp,
) {
    val appearance = rememberStatusAppearance(status)

    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = verticalPadding),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        LabeledValue(
            label = {
                WrapSafeText(
                    text = label,
                    style = DuckTypography.Callout,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            },
            value = {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Icon(
                        imageVector = statusIcon ?: appearance.icon,
                        contentDescription = null,
                        tint = appearance.iconTint,
                        modifier = Modifier.size(16.dp),
                    )
                    WrapSafeText(
                        text = value,
                        modifier = valueModifier,
                        style = DuckTypography.CalloutEmphasized,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            },
        )
        detail?.takeIf { it.isNotBlank() }?.let { resolvedDetail ->
            WrapSafeText(
                text = resolvedDetail,
                modifier = Modifier.fillMaxWidth(),
                style = DuckTypography.Footnote.copy(
                    fontFamily = if (detailMonospace) FontFamily.Monospace else DuckTypography.Footnote.fontFamily,
                ),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/**
 * Sets the value at the end of the label's line when both fit on one line, as a settings row
 * does, and under the label otherwise, so a long value keeps its full width instead of wrapping in
 * a narrow column.
 */
@Composable
private fun LabeledValue(
    label: @Composable () -> Unit,
    value: @Composable () -> Unit,
) {
    Layout(
        contents = listOf(label, value),
        modifier = Modifier.fillMaxWidth(),
    ) { (labelMeasurables, valueMeasurables), constraints ->
        val labelMeasurable = labelMeasurables.single()
        val valueMeasurable = valueMeasurables.single()
        val gap = LabelValueGap.roundToPx()
        val labelWidth = labelMeasurable.maxIntrinsicWidth(Constraints.Infinity)
        val valueWidth = valueMeasurable.maxIntrinsicWidth(Constraints.Infinity)
        val width = if (constraints.hasBoundedWidth) {
            constraints.maxWidth
        } else {
            labelWidth + gap + valueWidth
        }

        if (labelWidth + gap + valueWidth <= width) {
            val valuePlaceable = valueMeasurable.measure(Constraints(maxWidth = width))
            val labelPlaceable = labelMeasurable.measure(
                Constraints(maxWidth = (width - valuePlaceable.width - gap).coerceAtLeast(0)),
            )
            val height = maxOf(labelPlaceable.height, valuePlaceable.height)
            layout(width, height) {
                labelPlaceable.placeRelative(0, (height - labelPlaceable.height) / 2)
                valuePlaceable.placeRelative(width - valuePlaceable.width, (height - valuePlaceable.height) / 2)
            }
        } else {
            val labelPlaceable = labelMeasurable.measure(Constraints(maxWidth = width))
            val valuePlaceable = valueMeasurable.measure(Constraints(maxWidth = width))
            val spacing = StackedGap.roundToPx()
            layout(width, labelPlaceable.height + spacing + valuePlaceable.height) {
                labelPlaceable.placeRelative(0, 0)
                valuePlaceable.placeRelative(0, labelPlaceable.height + spacing)
            }
        }
    }
}
