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

package com.eltavine.duckdetector.features.dangerousapps.ui.card

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsPackageHistoryModel

@Composable
internal fun DangerousAppsPackageHistorySection(history: DangerousAppsPackageHistoryModel) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        WrapSafeText(
            text = history.summary,
            style = DuckTypography.Footnote,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        history.packages.forEach { item ->
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                WrapSafeText(
                    text = item.appName,
                    style = DuckTypography.CalloutEmphasized,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                WrapSafeText(
                    text = item.packageName,
                    style = DuckTypography.Footnote.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
