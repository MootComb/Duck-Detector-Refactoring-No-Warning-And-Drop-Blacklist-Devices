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

package com.eltavine.duckdetector.features.rootmanagers.ui.card

import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Policy
import androidx.compose.material.icons.rounded.Search
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.eltavine.duckdetector.core.ui.R as CoreUiR
import com.eltavine.duckdetector.core.ui.components.DetectorCardFrame
import com.eltavine.duckdetector.core.ui.components.DetectorDetailRowBlock
import com.eltavine.duckdetector.core.ui.components.DetectorHairline
import com.eltavine.duckdetector.core.ui.components.DetectorSectionFrame
import com.eltavine.duckdetector.core.ui.components.highestSectionSeverity
import com.eltavine.duckdetector.core.ui.copyPlainTextToClipboard
import com.eltavine.duckdetector.features.rootmanagers.presentation.model.RootManagersCardModel
import com.eltavine.duckdetector.features.rootmanagers.presentation.model.RootManagersDetailRowModel
import com.eltavine.duckdetector.features.rootmanagers.ui.R

@Composable
internal fun RootManagersDetectorCard(
    model: RootManagersCardModel,
    modifier: Modifier = Modifier,
) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.Policy,
        modifier = modifier,
    ) {
        RootManagersRowSection(
            title = stringResource(R.string.root_managers_section_matches),
            icon = Icons.Rounded.Search,
            rows = model.entryRows,
            showDivider = model.profileRows.isNotEmpty() || model.scanRows.isNotEmpty(),
        )
        RootManagersRowSection(
            title = stringResource(R.string.root_managers_section_profiles),
            icon = Icons.Rounded.Policy,
            rows = model.profileRows,
            showDivider = model.scanRows.isNotEmpty(),
        )
        RootManagersRowSection(
            title = stringResource(R.string.root_managers_section_scan),
            icon = Icons.Rounded.Info,
            rows = model.scanRows,
            showDivider = false,
        )
    }
}

@Composable
private fun RootManagersRowSection(
    title: String,
    icon: ImageVector,
    rows: List<RootManagersDetailRowModel>,
    showDivider: Boolean,
) {
    if (rows.isEmpty()) {
        return
    }
    DetectorSectionFrame(
        title = title,
        icon = icon,
        severity = highestSectionSeverity(rows.map { row -> row.status }),
        showDivider = showDivider,
    ) {
        rows.forEachIndexed { index, row ->
            RootManagersDetailRow(row)
            if (index < rows.lastIndex) {
                DetectorHairline()
            }
        }
    }
}

@Composable
private fun RootManagersDetailRow(
    row: RootManagersDetailRowModel,
) {
    val context = LocalContext.current
    val clipboardLabel = stringResource(R.string.root_managers_diagnostic_clipboard_label)
    val copiedToast = stringResource(CoreUiR.string.tee_diagnostic_copied_toast)
    val copyText = row.hiddenCopyText
    val rowModifier = if (copyText != null) {
        Modifier.combinedClickable(
            interactionSource = remember { MutableInteractionSource() },
            indication = null,
            onClick = {},
            onDoubleClick = {
                // Keep every node's full detail off the visible card but one double tap away for
                // development, matching the other detectors' hidden-copy rows.
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
