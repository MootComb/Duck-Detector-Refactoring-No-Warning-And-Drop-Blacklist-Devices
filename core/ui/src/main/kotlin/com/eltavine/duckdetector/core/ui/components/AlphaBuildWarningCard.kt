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

package com.eltavine.duckdetector.core.ui.components

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.OpenInNew
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.material.icons.rounded.Download
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material.icons.rounded.Science
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.components.DuckButtonDefaults
import com.eltavine.duckdetector.core.designsystem.theme.ContinuousCornerShape
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.designsystem.theme.MotionTokens
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import com.eltavine.duckdetector.core.ui.R

private val BadgeShape = ContinuousCornerShape(18.dp)

// The notice text starts after the icon and its gap, which is where each separator starts too.
private val NoticeTextInset = 50.dp

@Composable
internal fun AlphaBuildWarningCard(
    versionName: String,
    remainingSeconds: Int,
    onOpenGitHub: () -> Unit,
    onOpenTelegram: () -> Unit,
    onContinue: () -> Unit,
) {
    val palette = DuckTheme.palette
    val canDismiss = remainingSeconds == 0
    Box(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp),
        contentAlignment = Alignment.Center,
    ) {
        Column(
            modifier = Modifier
                .widthIn(max = 440.dp)
                .fillMaxWidth()
                .background(color = palette.groupedSurface, shape = ShapeTokens.CornerExtraLargeIncreased)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 22.dp, vertical = 26.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(64.dp)
                    .background(color = palette.groupedInset, shape = BadgeShape),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Rounded.Science,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.size(34.dp),
                )
            }

            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                WrapSafeText(
                    text = stringResource(R.string.alpha_title),
                    style = DuckTypography.Title2,
                    color = MaterialTheme.colorScheme.onSurface,
                    textAlign = TextAlign.Center,
                )
                WrapSafeText(
                    text = "v$versionName",
                    modifier = Modifier
                        .background(color = palette.groupedInset, shape = ShapeTokens.CornerFull)
                        .padding(horizontal = 12.dp, vertical = 4.dp),
                    style = DuckTypography.Footnote.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }

            WrapSafeText(
                text = stringResource(R.string.alpha_message),
                style = DuckTypography.Callout,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(color = palette.groupedInset, shape = ShapeTokens.CornerLarge),
            ) {
                AlphaNoticeRow(
                    icon = Icons.Rounded.WarningAmber,
                    text = stringResource(R.string.alpha_warning_runtime),
                )
                DetectorHairline(startInset = NoticeTextInset)
                AlphaNoticeRow(
                    icon = Icons.Rounded.BugReport,
                    text = stringResource(R.string.alpha_warning_report),
                )
                DetectorHairline(startInset = NoticeTextInset)
                AlphaNoticeRow(
                    icon = Icons.Rounded.Download,
                    text = stringResource(R.string.alpha_warning_download),
                )
            }

            WrapSafeText(
                text = stringResource(R.string.alpha_helper),
                style = DuckTypography.Footnote,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                AlphaLinkButton(
                    iconResId = R.drawable.ic_github,
                    label = stringResource(R.string.social_github),
                    onClick = onOpenGitHub,
                    modifier = Modifier.weight(1f),
                )
                AlphaLinkButton(
                    iconResId = R.drawable.ic_telegram,
                    label = stringResource(R.string.social_telegram),
                    onClick = onOpenTelegram,
                    modifier = Modifier.weight(1f),
                )
            }

            Button(
                onClick = onContinue,
                enabled = canDismiss,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 6.dp),
                colors = DuckButtonDefaults.filledColors(),
                contentPadding = DuckButtonDefaults.LargeContentPadding,
            ) {
                AnimatedContent(
                    targetState = canDismiss,
                    transitionSpec = {
                        fadeIn(MotionTokens.FadeInOut) togetherWith fadeOut(MotionTokens.FadeInOut)
                    },
                    label = "alphaContinue",
                ) { ready ->
                    WrapSafeText(
                        text = if (ready) {
                            stringResource(R.string.alpha_continue)
                        } else {
                            stringResource(R.string.alpha_continue_waiting, remainingSeconds)
                        },
                        style = DuckTypography.Headline,
                    )
                }
            }

            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Icon(
                    imageVector = Icons.Rounded.Schedule,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(14.dp),
                )
                WrapSafeText(
                    text = if (canDismiss) {
                        stringResource(R.string.alpha_dismiss_ready)
                    } else {
                        stringResource(R.string.alpha_dismiss_waiting, remainingSeconds)
                    },
                    style = DuckTypography.Footnote,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun AlphaNoticeRow(
    icon: ImageVector,
    text: String,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 14.dp, vertical = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier
                .size(24.dp)
                .background(color = DuckTheme.palette.groupedSurface, shape = ShapeTokens.CornerMedium),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.size(16.dp),
            )
        }
        WrapSafeText(
            text = text,
            modifier = Modifier.weight(1f),
            style = DuckTypography.Footnote,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
private fun AlphaLinkButton(
    iconResId: Int,
    label: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Button(
        onClick = onClick,
        modifier = modifier,
        colors = DuckButtonDefaults.tonalColors(),
        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 10.dp),
    ) {
        Icon(
            painter = painterResource(iconResId),
            contentDescription = null,
            modifier = Modifier.size(18.dp),
        )
        Spacer(modifier = Modifier.width(8.dp))
        WrapSafeText(text = label, style = DuckTypography.CalloutEmphasized)
        Spacer(modifier = Modifier.width(4.dp))
        Icon(
            imageVector = Icons.AutoMirrored.Rounded.OpenInNew,
            contentDescription = null,
            modifier = Modifier.size(14.dp),
        )
    }
}
