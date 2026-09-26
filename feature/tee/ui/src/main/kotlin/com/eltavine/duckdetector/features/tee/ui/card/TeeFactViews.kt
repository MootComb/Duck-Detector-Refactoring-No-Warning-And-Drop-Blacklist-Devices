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

package com.eltavine.duckdetector.features.tee.ui.card

import android.content.ClipData
import android.content.ClipboardManager
import android.widget.Toast
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Cable
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.Hub
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.NetworkCheck
import androidx.compose.material.icons.rounded.Policy
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material.icons.rounded.VpnKey
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.R as CoreUiR
import com.eltavine.duckdetector.core.ui.components.DetectorDetailRowBlock
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import com.eltavine.duckdetector.core.ui.theme.ShapeTokens
import com.eltavine.duckdetector.features.tee.presentation.model.TeeFactGroupModel
import com.eltavine.duckdetector.features.tee.presentation.model.TeeFactIcon
import com.eltavine.duckdetector.features.tee.presentation.model.TeeFactRowModel
import com.eltavine.duckdetector.features.tee.presentation.model.TeeHeaderFactModel
import com.eltavine.duckdetector.features.tee.presentation.model.TeeHighlightSignalModel
import com.eltavine.duckdetector.features.tee.ui.R

@Composable
internal fun TeeFactPairCard(
    primary: TeeHeaderFactModel,
    secondary: TeeHeaderFactModel,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = ShapeTokens.CornerExtraLarge,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            TeeFactPairRow(fact = primary)
            HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.42f),
                thickness = 1.dp,
            )
            TeeFactPairRow(fact = secondary)
        }
    }
}

@Composable
private fun TeeFactPairRow(
    fact: TeeHeaderFactModel,
) {
    val appearance = rememberStatusAppearance(fact.status)
    Column(
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Icon(
                imageVector = appearance.icon,
                contentDescription = null,
                tint = appearance.iconTint,
                modifier = Modifier.size(15.dp),
            )
            WrapSafeText(
                text = fact.label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        WrapSafeText(
            text = fact.value,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
internal fun TeeHighlightPill(
    signal: TeeHighlightSignalModel,
) {
    val appearance = rememberStatusAppearance(signal.status)
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = ShapeTokens.CornerFull,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Icon(
                imageVector = appearance.icon,
                contentDescription = null,
                tint = appearance.iconTint,
                modifier = Modifier.size(16.dp),
            )
            WrapSafeText(
                text = "${signal.label}: ${signal.value}",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}

@Composable
internal fun TeeFactGroup(
    group: TeeFactGroupModel,
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        shape = ShapeTokens.CornerExtraLarge,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            WrapSafeText(
                text = group.title,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                group.rows.forEachIndexed { index, row ->
                    TeeFactRow(row = row)
                    if (index < group.rows.lastIndex) {
                        HorizontalDivider(
                            color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.42f),
                            thickness = 1.dp,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun TeeFactRow(
    row: TeeFactRowModel,
) {
    val context = LocalContext.current
    val clipboardLabel = stringResource(R.string.tee_diagnostic_clipboard_label)
    val copiedToast = stringResource(CoreUiR.string.tee_diagnostic_copied_toast)
    val valueModifier = if (row.hiddenCopyText != null) {
        // 诊断复制是故意做成“无显式 affordance”的双击隐藏入口，避免把正常读卡 UI 变成调试工具面板。
        // Diagnostic copy is intentionally a no-affordance double-tap entry so the normal card UI does not turn into a visible debugging panel.
        Modifier.combinedClickable(
            interactionSource = remember { MutableInteractionSource() },
            indication = null,
            onClick = {},
            onDoubleClick = {
                context.getSystemService(ClipboardManager::class.java)
                    ?.setPrimaryClip(ClipData.newPlainText(clipboardLabel, row.hiddenCopyText))
                Toast.makeText(context, copiedToast, Toast.LENGTH_SHORT).show()
            },
        )
    } else {
        Modifier
    }
    DetectorDetailRowBlock(
        label = row.label,
        value = row.value,
        status = row.status,
        statusIcon = iconFor(row.icon),
        verticalPadding = 0.dp,
        valueModifier = valueModifier,
    )
}

private fun iconFor(icon: TeeFactIcon): ImageVector {
    return when (icon) {
        TeeFactIcon.TRUST -> Icons.Rounded.Security
        TeeFactIcon.CERTIFICATE -> Icons.Rounded.VerifiedUser
        TeeFactIcon.NETWORK -> Icons.Rounded.NetworkCheck
        TeeFactIcon.RKP -> Icons.Rounded.Hub
        TeeFactIcon.KEY -> Icons.Rounded.Key
        TeeFactIcon.BOOT -> Icons.Rounded.Lock
        TeeFactIcon.PATCH -> Icons.Rounded.Policy
        TeeFactIcon.DEVICE -> Icons.Rounded.Fingerprint
        TeeFactIcon.APP -> Icons.Rounded.Shield
        TeeFactIcon.AUTH -> Icons.Rounded.VpnKey
        TeeFactIcon.KEYSTORE -> Icons.Rounded.Cable
        TeeFactIcon.TIMING -> Icons.Rounded.Speed
        TeeFactIcon.STRONGBOX -> Icons.Rounded.Security
        TeeFactIcon.NATIVE -> Icons.Rounded.Memory
        TeeFactIcon.SOTER -> Icons.Rounded.VerifiedUser
        TeeFactIcon.WARNING -> Icons.Rounded.CrisisAlert
    }
}
