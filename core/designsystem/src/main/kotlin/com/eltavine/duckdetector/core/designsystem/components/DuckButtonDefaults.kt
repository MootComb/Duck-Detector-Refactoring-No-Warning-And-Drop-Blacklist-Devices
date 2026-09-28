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

package com.eltavine.duckdetector.core.designsystem.components

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.material3.ButtonColors
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme

/**
 * Colors and padding for Material's [androidx.compose.material3.Button], whose default shape is
 * already a capsule, in the three roles the app's buttons take.
 */
public object DuckButtonDefaults {
    /**
     * The main action of a page or dialog. A disabled one keeps a legible label, because here a
     * disabled button still says what it is waiting for.
     */
    @Composable
    public fun filledColors(): ButtonColors = ButtonDefaults.buttonColors(
        disabledContainerColor = DuckTheme.palette.groupedInset,
        disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
    )

    /** A secondary action: an accent label on the inset fill. */
    @Composable
    public fun tonalColors(): ButtonColors = ButtonDefaults.buttonColors(
        containerColor = DuckTheme.palette.groupedInset,
        contentColor = MaterialTheme.colorScheme.primary,
    )

    /** An action that stands out from its neighbours without filling in: an accent wash. */
    @Composable
    public fun tintedColors(): ButtonColors = ButtonDefaults.buttonColors(
        containerColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.14f),
        contentColor = MaterialTheme.colorScheme.primary,
    )

    /** Padding of a full-width button that ends a page, a card or a dialog. */
    public val LargeContentPadding: PaddingValues = PaddingValues(horizontal = 20.dp, vertical = 14.dp)
}
