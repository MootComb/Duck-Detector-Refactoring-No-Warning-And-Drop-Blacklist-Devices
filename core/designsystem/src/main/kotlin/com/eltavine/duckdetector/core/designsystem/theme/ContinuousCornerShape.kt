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

package com.eltavine.duckdetector.core.designsystem.theme

import androidx.compose.foundation.shape.CornerBasedShape
import androidx.compose.foundation.shape.CornerSize
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.geometry.toRect
import androidx.compose.ui.graphics.Outline
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.graphics.asComposePath
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.util.lerp
import androidx.graphics.shapes.CornerRounding
import androidx.graphics.shapes.RoundedPolygon
import androidx.graphics.shapes.rectangle
import androidx.graphics.shapes.toPath

/**
 * A rounded rectangle whose corners ease out of their edges instead of meeting them in a circular
 * arc, like Apple's continuous corners. The outline is the smoothed corner rounding of AndroidX
 * graphics-shapes, which gives up smoothing before radius where an edge is too short, so a corner
 * of half the height still closes into a semicircle.
 */
public class ContinuousCornerShape(
    topStart: CornerSize,
    topEnd: CornerSize,
    bottomEnd: CornerSize,
    bottomStart: CornerSize,
) : CornerBasedShape(topStart, topEnd, bottomEnd, bottomStart) {

    override fun createOutline(
        size: Size,
        topStart: Float,
        topEnd: Float,
        bottomEnd: Float,
        bottomStart: Float,
        layoutDirection: LayoutDirection,
    ): Outline {
        if (size.isEmpty() || topStart + topEnd + bottomEnd + bottomStart == 0f) {
            return Outline.Rectangle(size.toRect())
        }
        val polygon = continuousRectangle(size, topStart, topEnd, bottomEnd, bottomStart, layoutDirection)
        return Outline.Generic(polygon.toPath().asComposePath())
    }

    override fun copy(
        topStart: CornerSize,
        topEnd: CornerSize,
        bottomEnd: CornerSize,
        bottomStart: CornerSize,
    ): ContinuousCornerShape = ContinuousCornerShape(topStart, topEnd, bottomEnd, bottomStart)

    override fun lerp(other: Any?, t: Float): Any? {
        val target = when (other) {
            null, RectangleShape -> ContinuousCornerShape(0.dp)
            is ContinuousCornerShape -> other
            else -> return null
        }
        return ContinuousCornerShape(
            topStart = lerp(topStart, target.topStart, t),
            topEnd = lerp(topEnd, target.topEnd, t),
            bottomEnd = lerp(bottomEnd, target.bottomEnd, t),
            bottomStart = lerp(bottomStart, target.bottomStart, t),
        )
    }

    override fun toString(): String =
        "ContinuousCornerShape(topStart = $topStart, topEnd = $topEnd, bottomEnd = $bottomEnd, " +
            "bottomStart = $bottomStart)"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ContinuousCornerShape) return false
        return topStart == other.topStart &&
            topEnd == other.topEnd &&
            bottomEnd == other.bottomEnd &&
            bottomStart == other.bottomStart
    }

    override fun hashCode(): Int {
        var result = topStart.hashCode()
        result = 31 * result + topEnd.hashCode()
        result = 31 * result + bottomEnd.hashCode()
        result = 31 * result + bottomStart.hashCode()
        return result
    }
}

public fun ContinuousCornerShape(radius: Dp): ContinuousCornerShape =
    ContinuousCornerShape(CornerSize(radius))

public fun ContinuousCornerShape(corner: CornerSize): ContinuousCornerShape =
    ContinuousCornerShape(corner, corner, corner, corner)

public fun ContinuousCornerShape(
    topStart: Dp = 0.dp,
    topEnd: Dp = 0.dp,
    bottomEnd: Dp = 0.dp,
    bottomStart: Dp = 0.dp,
): ContinuousCornerShape = ContinuousCornerShape(
    topStart = CornerSize(topStart),
    topEnd = CornerSize(topEnd),
    bottomEnd = CornerSize(bottomEnd),
    bottomStart = CornerSize(bottomStart),
)

// Figma's corner smoothing marks 60 % as the setting that matches Apple's continuous corners.
internal const val ContinuousCornerSmoothing: Float = 0.6f

/** A rectangle of [size] at the origin, each corner rounded by its radius in pixels and smoothed. */
internal fun continuousRectangle(
    size: Size,
    topStart: Float,
    topEnd: Float,
    bottomEnd: Float,
    bottomStart: Float,
    layoutDirection: LayoutDirection,
): RoundedPolygon {
    val ltr = layoutDirection == LayoutDirection.Ltr
    val topLeft = if (ltr) topStart else topEnd
    val topRight = if (ltr) topEnd else topStart
    val bottomRight = if (ltr) bottomEnd else bottomStart
    val bottomLeft = if (ltr) bottomStart else bottomEnd
    return RoundedPolygon.rectangle(
        width = size.width,
        height = size.height,
        // graphics-shapes lists a rectangle's vertices starting from its bottom right corner.
        perVertexRounding = listOf(bottomRight, bottomLeft, topLeft, topRight).map { radius ->
            CornerRounding(radius = radius, smoothing = ContinuousCornerSmoothing)
        },
        centerX = size.width / 2f,
        centerY = size.height / 2f,
    )
}

private fun lerp(start: CornerSize, stop: CornerSize, fraction: Float): CornerSize =
    object : CornerSize {
        override fun toPx(shapeSize: Size, density: Density): Float = lerp(
            start.toPx(shapeSize, density),
            stop.toPx(shapeSize, density),
            fraction,
        )
    }
