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
import androidx.compose.ui.unit.dp
import org.junit.Assert.assertEquals
import org.junit.Test

class SettingsItemShapesTest {
    private val inner = CornerSize(4.dp)
    private val outer = CornerSize(32.dp)

    @Test
    fun onlyTheGroupEdgesTakeTheOuterCorners() {
        assertCorners(segmentShape(0, 3, inner, outer), top = outer, bottom = inner)
        assertCorners(segmentShape(1, 3, inner, outer), top = inner, bottom = inner)
        assertCorners(segmentShape(2, 3, inner, outer), top = inner, bottom = outer)
    }

    @Test
    fun aSingleRowIsRoundedOnEverySide() {
        assertCorners(segmentShape(0, 1, inner, outer), top = outer, bottom = outer)
    }

    private fun assertCorners(shape: CornerBasedShape, top: CornerSize, bottom: CornerSize) {
        assertEquals(top, shape.topStart)
        assertEquals(top, shape.topEnd)
        assertEquals(bottom, shape.bottomStart)
        assertEquals(bottom, shape.bottomEnd)
    }
}
