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

package com.eltavine.duckdetector.core.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.ui.unit.dp

public val Shapes: Shapes = Shapes(
    extraSmall = RoundedCornerShape(4.dp),
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(12.dp),
    large = RoundedCornerShape(16.dp),
    extraLarge = RoundedCornerShape(28.dp),
)

public object ShapeTokens {
    public val CornerLarge: RoundedCornerShape = RoundedCornerShape(16.dp)
    public val CornerLargeIncreased: RoundedCornerShape = RoundedCornerShape(20.dp)
    public val CornerExtraLarge: RoundedCornerShape = RoundedCornerShape(28.dp)
    public val CornerExtraLargeIncreased: RoundedCornerShape = RoundedCornerShape(32.dp)
    public val CornerFull: RoundedCornerShape = RoundedCornerShape(50)
}
