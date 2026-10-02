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

package com.eltavine.duckdetector.features.tee.ui.card

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Details
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Verified
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.ui.components.DetectorActionButton
import com.eltavine.duckdetector.core.ui.components.DetectorCardFrame
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import com.eltavine.duckdetector.features.tee.presentation.model.TeeCardModel
import com.eltavine.duckdetector.features.tee.presentation.model.TeeFooterActionId
import com.eltavine.duckdetector.features.tee.presentation.model.TeeFooterActionModel
import com.eltavine.duckdetector.features.tee.presentation.model.TeeHeaderFact
import com.eltavine.duckdetector.features.tee.ui.TeeCertificatesDialog
import com.eltavine.duckdetector.features.tee.ui.TeeDetailsDialog

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun TeeDetectorCard(
    model: TeeCardModel,
    showDetailsDialog: Boolean,
    showCertificatesDialog: Boolean,
    onExpandedChange: (Boolean) -> Unit,
    onFooterAction: (TeeFooterActionId) -> Unit,
    onDismissDetails: () -> Unit,
    onDismissCertificates: () -> Unit,
    modifier: Modifier = Modifier,
) {
    if (showDetailsDialog) {
        TeeDetailsDialog(
            exportText = model.exportText,
            certificateCount = model.certificateSummary.certificates.size,
            onDismiss = onDismissDetails,
        )
    }

    if (showCertificatesDialog) {
        TeeCertificatesDialog(
            label = model.certificateSummary.label,
            count = model.certificateSummary.count,
            certificates = model.certificateSummary.certificates,
            onDismiss = onDismissCertificates,
        )
    }

    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.Security,
        modifier = modifier,
        expanded = model.isExpanded,
        onExpandedChange = onExpandedChange,
        headerFacts = {
            TeeCollapsedOverview(model = model)
        },
        footerActions = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                TeeNetworkBanner(model = model)
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    model.actions.forEach { action ->
                        TeeFooterButton(action = action, onClick = onFooterAction)
                    }
                }
            }
        },
    ) {
        if (model.highlightSignals.isNotEmpty()) {
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                model.highlightSignals.forEach { signal ->
                    TeeHighlightPill(signal = signal)
                }
            }
        }

        model.factGroups.forEach { group ->
            TeeFactGroup(group = group)
        }
    }
}

@Composable
private fun TeeCollapsedOverview(
    model: TeeCardModel,
) {
    val verdict = model.headerFacts.firstOrNull { it.fact == TeeHeaderFact.VERDICT } ?: return
    val score = model.headerFacts.firstOrNull { it.fact == TeeHeaderFact.SCORE } ?: return
    val tier = model.headerFacts.firstOrNull { it.fact == TeeHeaderFact.TIER } ?: return
    val trust = model.headerFacts.firstOrNull { it.fact == TeeHeaderFact.TRUST } ?: return

    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        model.rkpBadgeLabel?.let { label ->
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
            ) {
                TeeRkpBadge(label = label)
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.Top,
        ) {
            TeeFactPairCard(
                primary = verdict,
                secondary = score,
                modifier = Modifier.weight(1f),
            )
            TeeFactPairCard(
                primary = tier,
                secondary = trust,
                modifier = Modifier.weight(1f),
            )
        }
    }
}

@Composable
private fun TeeRkpBadge(
    label: String,
    modifier: Modifier = Modifier,
) {
    val appearance = rememberStatusAppearance(DetectorStatus.allClear())
    Row(
        modifier = modifier
            .background(color = appearance.tintWash, shape = ShapeTokens.CornerFull)
            .padding(start = 8.dp, end = 10.dp, top = 4.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(5.dp),
    ) {
        Icon(
            imageVector = Icons.Rounded.Verified,
            contentDescription = null,
            tint = appearance.iconTint,
            modifier = Modifier.size(14.dp),
        )
        WrapSafeText(
            text = label,
            style = DuckTypography.Caption,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
private fun TeeNetworkBanner(model: TeeCardModel) {
    val appearance = rememberStatusAppearance(model.networkState.status)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(color = DuckTheme.palette.groupedInset, shape = ShapeTokens.CornerLarge)
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(
            imageVector = appearance.icon,
            contentDescription = null,
            tint = appearance.iconTint,
            modifier = Modifier.size(20.dp),
        )
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            WrapSafeText(
                text = model.networkState.label,
                style = DuckTypography.CalloutEmphasized,
                color = MaterialTheme.colorScheme.onSurface,
            )
            WrapSafeText(
                text = model.networkState.summary,
                style = DuckTypography.Footnote,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun TeeFooterButton(
    action: TeeFooterActionModel,
    onClick: (TeeFooterActionId) -> Unit,
) {
    DetectorActionButton(
        label = action.counter?.let { "${action.label} (${it})" } ?: action.label,
        icon = when (action.id) {
            TeeFooterActionId.DETAILS -> Icons.Rounded.Details
            TeeFooterActionId.CERTIFICATES -> Icons.Rounded.VerifiedUser
            TeeFooterActionId.RESCAN -> Icons.Rounded.Refresh
        },
        onClick = { onClick(action.id) },
        enabled = action.enabled,
        prominent = action.id == TeeFooterActionId.RESCAN,
    )
}
