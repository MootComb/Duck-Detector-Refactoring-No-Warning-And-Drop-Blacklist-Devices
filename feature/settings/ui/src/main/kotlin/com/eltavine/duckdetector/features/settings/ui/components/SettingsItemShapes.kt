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

import androidx.compose.foundation.shape.CornerBasedShape
import androidx.compose.foundation.shape.CornerSize
import androidx.compose.material3.ListItemShapes
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import com.eltavine.duckdetector.core.designsystem.theme.ContinuousCornerShape
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens

/**
 * Shapes for the [index]th of [count] rows of a settings group. The group's outer corners match the
 * app's cards in every state; the inner corners follow the theme corners Material gives each
 * list-item state, so a pressed row still rounds away from its neighbours.
 */
@Composable
internal fun settingsItemShapes(index: Int, count: Int): ListItemShapes {
    val shapes = MaterialTheme.shapes
    return remember(index, count, shapes) {
        val outer = ShapeTokens.CornerExtraLargeIncreased.topStart
        fun shape(inner: CornerSize) = segmentShape(index, count, inner = inner, outer = outer)
        ListItemShapes(
            shape = shape(shapes.extraSmall.topStart),
            selectedShape = shape(shapes.large.topStart),
            pressedShape = shape(shapes.large.topStart),
            focusedShape = shape(shapes.large.topStart),
            hoveredShape = shape(shapes.medium.topStart),
            draggedShape = shape(shapes.large.topStart),
        )
    }
}

internal fun segmentShape(
    index: Int,
    count: Int,
    inner: CornerSize,
    outer: CornerSize,
): CornerBasedShape {
    val top = if (index == 0) outer else inner
    val bottom = if (index == count - 1) outer else inner
    return ContinuousCornerShape(topStart = top, topEnd = top, bottomEnd = bottom, bottomStart = bottom)
}
