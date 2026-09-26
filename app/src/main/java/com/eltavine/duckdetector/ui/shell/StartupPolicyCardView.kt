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

package com.eltavine.duckdetector.ui.shell

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.theme.ShapeTokens

@Composable
internal fun StartupPolicyCard(
    card: StartupPolicyCardUi,
) {
    val colors = card.tone.colors()
    Surface(
        shape = ShapeTokens.CornerExtraLarge,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 18.dp, vertical = 18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.Top,
                horizontalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .background(color = colors.container, shape = ShapeTokens.CornerLarge),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = card.icon,
                        contentDescription = null,
                        tint = colors.content,
                    )
                }

                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        WrapSafeText(
                            text = card.title,
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.weight(1f),
                        )
                        StatusBadge(
                            label = card.statusLabel,
                            containerColor = colors.container,
                            contentColor = colors.content,
                        )
                    }

                    WrapSafeText(
                        text = card.headline,
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }

            WrapSafeText(
                text = card.detail,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (card.primaryActionLabel != null || card.secondaryActionLabel != null) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    if (card.secondaryActionLabel != null && card.onSecondaryAction != null) {
                        OutlinedButton(onClick = card.onSecondaryAction) {
                            WrapSafeText(
                                text = card.secondaryActionLabel,
                                style = MaterialTheme.typography.labelLarge,
                            )
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                    }

                    if (card.primaryActionLabel != null && card.onPrimaryAction != null) {
                        FilledTonalButton(onClick = card.onPrimaryAction) {
                            WrapSafeText(
                                text = card.primaryActionLabel,
                                style = MaterialTheme.typography.labelLarge,
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun StatusBadge(
    label: String,
    containerColor: Color,
    contentColor: Color,
) {
    Surface(
        color = containerColor,
        shape = ShapeTokens.CornerFull,
    ) {
        WrapSafeText(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = contentColor,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
        )
    }
}

private data class StartupPolicyColors(
    val container: Color,
    val content: Color,
)

private fun StartupPolicyTone.colors(): StartupPolicyColors {
    return when (this) {
        StartupPolicyTone.REQUIRED -> StartupPolicyColors(
            container = Color(0xFFFDE7D9),
            content = Color(0xFF9A3412),
        )

        StartupPolicyTone.READY -> StartupPolicyColors(
            container = Color(0xFFDDF4E4),
            content = Color(0xFF166534),
        )

        StartupPolicyTone.ACKNOWLEDGED -> StartupPolicyColors(
            container = Color(0xFFE8ECF8),
            content = Color(0xFF334155),
        )

        StartupPolicyTone.SUPPORT -> StartupPolicyColors(
            container = Color(0xFFE9E7FF),
            content = Color(0xFF5B43B5),
        )
    }
}
