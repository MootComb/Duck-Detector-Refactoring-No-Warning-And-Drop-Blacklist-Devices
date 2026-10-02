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

package com.eltavine.duckdetector.core.designsystem.theme

import androidx.compose.ui.geometry.Size
import androidx.compose.ui.unit.LayoutDirection
import androidx.graphics.shapes.RoundedPolygon
import kotlin.math.abs
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ContinuousCornerShapeTest {
    private val size = Size(width = 200f, height = 100f)

    @Test
    fun outlineFillsItsBoundsWithoutLeavingThem() {
        val polygon = continuousRectangle(size, 20f, 20f, 20f, 20f, LayoutDirection.Ltr)

        val bounds = polygon.calculateBounds(approximate = false)

        assertArrayEquals(floatArrayOf(0f, 0f, 200f, 100f), bounds, EPSILON)
    }

    @Test
    fun smoothedCornerLeavesItsEdgesFartherOutThanItsRadius() {
        val anchors = continuousRectangle(size, 20f, 0f, 0f, 0f, LayoutDirection.Ltr).anchors()

        val leavesTopEdgeAt = anchors.filter { (_, y) -> abs(y) < EPSILON }.minOf { (x, _) -> x }
        val leavesStartEdgeAt = anchors.filter { (x, _) -> abs(x) < EPSILON }.minOf { (_, y) -> y }

        assertEquals((1 + ContinuousCornerSmoothing) * 20f, leavesTopEdgeAt, EPSILON)
        assertEquals((1 + ContinuousCornerSmoothing) * 20f, leavesStartEdgeAt, EPSILON)
    }

    @Test
    fun unroundedCornersStaySharp() {
        val anchors = continuousRectangle(size, 20f, 0f, 0f, 0f, LayoutDirection.Ltr).anchors()

        assertTrue(anchors.hasPoint(200f, 0f))
        assertTrue(anchors.hasPoint(200f, 100f))
        assertTrue(anchors.hasPoint(0f, 100f))
        assertFalse(anchors.hasPoint(0f, 0f))
    }

    @Test
    fun startCornersFollowTheLayoutDirection() {
        val anchors = continuousRectangle(size, 20f, 0f, 0f, 0f, LayoutDirection.Rtl).anchors()

        assertTrue(anchors.hasPoint(0f, 0f))
        assertFalse(anchors.hasPoint(200f, 0f))
    }

    @Test
    fun cornersOfHalfTheHeightCloseIntoASemicircle() {
        val polygon = continuousRectangle(size, 50f, 50f, 50f, 50f, LayoutDirection.Ltr)

        val bounds = polygon.calculateBounds(approximate = false)
        val anchors = polygon.anchors()

        assertArrayEquals(floatArrayOf(0f, 0f, 200f, 100f), bounds, EPSILON)
        // With no straight part left on the short edges, each end reaches only its middle.
        assertTrue(anchors.hasPoint(0f, 50f))
        assertFalse(anchors.any { (x, y) -> abs(x) < EPSILON && abs(y - 50f) > EPSILON })
    }

    private fun RoundedPolygon.anchors(): List<Pair<Float, Float>> = cubics.flatMap { cubic ->
        listOf(cubic.anchor0X to cubic.anchor0Y, cubic.anchor1X to cubic.anchor1Y)
    }

    private fun List<Pair<Float, Float>>.hasPoint(x: Float, y: Float): Boolean =
        any { (px, py) -> abs(px - x) < EPSILON && abs(py - y) < EPSILON }

    private companion object {
        const val EPSILON = 1e-2f
    }
}
