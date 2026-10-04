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

package com.eltavine.duckdetector.features.mount.ui.card

import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AccountTree
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.FolderOpen
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Storage
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.components.DetectorCardFrame
import com.eltavine.duckdetector.core.ui.components.DetectorDetailRowBlock
import com.eltavine.duckdetector.core.ui.components.DetectorFact
import com.eltavine.duckdetector.core.ui.components.DetectorFactPair
import com.eltavine.duckdetector.core.ui.components.DetectorHairline
import com.eltavine.duckdetector.core.ui.components.DetectorSectionFrame
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.copyPlainTextToClipboard
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import com.eltavine.duckdetector.features.mount.ui.R
import com.eltavine.duckdetector.features.mount.presentation.model.MountCardModel
import com.eltavine.duckdetector.features.mount.presentation.model.MountDetailRowModel
import com.eltavine.duckdetector.features.mount.presentation.model.MountHeaderFact
import com.eltavine.duckdetector.features.mount.presentation.model.MountHeaderFactModel
import com.eltavine.duckdetector.features.mount.presentation.model.MountImpactItemModel
import com.eltavine.duckdetector.core.ui.R as CoreUiR

@Composable
internal fun MountDetectorCard(
    model: MountCardModel,
    modifier: Modifier = Modifier,
) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.Storage,
        modifier = modifier,
        headerFacts = {
            MountCollapsedOverview(model = model)
        },
    ) {
        if (model.procMountViewRows.isNotEmpty()) {
            MountDetailSection(
                title = "Isolated process mounts",
                icon = Icons.Rounded.AccountTree,
                rows = model.procMountViewRows,
            )
        }

        if (model.artifactRows.isNotEmpty()) {
            MountDetailSection(
                title = "Root artifacts",
                icon = Icons.Rounded.FolderOpen,
                rows = model.artifactRows,
            )
        }

        if (model.runtimeRows.isNotEmpty()) {
            MountDetailSection(
                title = "Runtime mounts",
                icon = Icons.Rounded.Storage,
                rows = model.runtimeRows,
            )
        }

        if (model.filesystemRows.isNotEmpty()) {
            MountDetailSection(
                title = "Filesystem",
                icon = Icons.Rounded.Memory,
                rows = model.filesystemRows,
            )
        }

        if (model.consistencyRows.isNotEmpty()) {
            MountDetailSection(
                title = "Namespace and consistency",
                icon = Icons.Rounded.AccountTree,
                rows = model.consistencyRows,
            )
        }

        if (model.impactItems.isNotEmpty()) {
            MountImpactSection(
                title = "Impact",
                icon = Icons.Rounded.CrisisAlert,
                items = model.impactItems,
            )
        }

        if (model.methodRows.isNotEmpty()) {
            MountDetailSection(
                title = "Detection methods",
                icon = Icons.Rounded.Search,
                rows = model.methodRows,
            )
        }

        if (model.scanRows.isNotEmpty()) {
            MountDetailSection(
                title = "Scan summary",
                icon = Icons.Rounded.Info,
                rows = model.scanRows,
            )
        }
    }
}

@Composable
private fun MountCollapsedOverview(
    model: MountCardModel,
) {
    val critical = model.headerFacts.firstOrNull { it.fact == MountHeaderFact.CRITICAL } ?: return
    val review = model.headerFacts.firstOrNull { it.fact == MountHeaderFact.REVIEW } ?: return
    val coverage = model.headerFacts.firstOrNull { it.fact == MountHeaderFact.COVERAGE } ?: return
    val native = model.headerFacts.firstOrNull { it.fact == MountHeaderFact.NATIVE } ?: return

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        MountFactPairCard(
            primary = critical,
            secondary = review,
            modifier = Modifier.weight(1f),
        )
        MountFactPairCard(
            primary = coverage,
            secondary = native,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun MountFactPairCard(
    primary: MountHeaderFactModel,
    secondary: MountHeaderFactModel,
    modifier: Modifier = Modifier,
) {
    DetectorFactPair(
        primary = primary.asDetectorFact(),
        secondary = secondary.asDetectorFact(),
        modifier = modifier,
    )
}

private fun MountHeaderFactModel.asDetectorFact() =
    DetectorFact(label = label, value = value, status = status)

@Composable
private fun MountDetailSection(
    title: String,
    icon: ImageVector,
    rows: List<MountDetailRowModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
            rows.forEachIndexed { index, row ->
                MountDetailRow(row = row)
                if (index < rows.lastIndex) {
                    DetectorHairline()
                }
            }
        }
    }
}

@Composable
private fun MountDetailRow(
    row: MountDetailRowModel,
) {
    val context = LocalContext.current
    val clipboardLabel = stringResource(R.string.mount_diagnostic_clipboard_label)
    val copiedToast = stringResource(CoreUiR.string.tee_diagnostic_copied_toast)
    val copyText = row.hiddenCopyText
    val rowModifier = if (copyText != null) {
        Modifier.combinedClickable(
            interactionSource = remember { MutableInteractionSource() },
            indication = null,
            onClick = {},
            onDoubleClick = {
                copyPlainTextToClipboard(context, clipboardLabel, copyText, copiedToast)
            },
        )
    } else {
        Modifier
    }
    DetectorDetailRowBlock(
        label = row.label,
        value = row.value,
        status = row.status,
        modifier = rowModifier,
        detail = row.detail,
        detailMonospace = row.detailMonospace,
    )
}

@Composable
private fun MountImpactSection(
    title: String,
    icon: ImageVector,
    items: List<MountImpactItemModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items.forEach { item ->
                MountImpactRow(item = item)
            }
        }
    }
}

@Composable
private fun MountImpactRow(
    item: MountImpactItemModel,
) {
    val appearance = rememberStatusAppearance(item.status)
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Icon(
            imageVector = appearance.icon,
            contentDescription = null,
            tint = appearance.iconTint,
            modifier = Modifier.size(16.dp),
        )
        WrapSafeText(
            text = item.text,
            modifier = Modifier.fillMaxWidth(),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
