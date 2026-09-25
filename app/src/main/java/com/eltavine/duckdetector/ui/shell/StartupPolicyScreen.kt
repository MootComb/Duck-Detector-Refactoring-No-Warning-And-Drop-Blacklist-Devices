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
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import com.eltavine.duckdetector.core.detector.ConsentDecision
import com.eltavine.duckdetector.core.detector.ConsentId
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.theme.ShapeTokens
import com.eltavine.duckdetector.notifications.ScanNotificationPermissionState
import com.eltavine.duckdetector.notifications.preferences.ScanNotificationPrefs

data class StartupPackageVisibilityState(
    val visibility: InstalledPackageVisibility,
    val visiblePackageCount: Int,
    val suspiciouslyLowInventory: Boolean,
)

@Composable
internal fun StartupPolicyScreen(
    gateState: StartupGateState,
    notificationPrefs: ScanNotificationPrefs?,
    notificationPermissionState: ScanNotificationPermissionState,
    consentCards: List<DetectorConsentCard>,
    consentDecisions: Map<ConsentId, ConsentDecision>?,
    packageVisibilityState: StartupPackageVisibilityState?,
    packageVisibilityReviewAcknowledged: Boolean,
    onAllowNotifications: () -> Unit,
    onSkipNotifications: () -> Unit,
    onOpenLiveUpdateSettings: () -> Unit,
    onUseRegularNotifications: () -> Unit,
    onDecideConsent: (DetectorConsentCard, granted: Boolean) -> Unit,
    onAcknowledgePackageVisibility: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val cards = if (
        gateState == StartupGateState.LOADING ||
        notificationPrefs == null ||
        consentDecisions == null ||
        packageVisibilityState == null
    ) {
        emptyList()
    } else {
        listOf(
            notificationPolicyCard(
                notificationPrefs = notificationPrefs,
                permissionState = notificationPermissionState,
                onAllowNotifications = onAllowNotifications,
                onSkipNotifications = onSkipNotifications,
            ),
            liveUpdatePolicyCard(
                notificationPrefs = notificationPrefs,
                permissionState = notificationPermissionState,
                onOpenLiveUpdateSettings = onOpenLiveUpdateSettings,
                onUseRegularNotifications = onUseRegularNotifications,
            ),
        ) + consentCards.map { consentCard ->
            consentPolicyCard(
                prompt = consentCard.card.prompt,
                decision = consentDecisions.getValue(consentCard.consent.id),
                onDecide = { granted -> onDecideConsent(consentCard, granted) },
            )
        } + listOf(
            packageManagerPolicyCard(
                packageVisibilityState = packageVisibilityState,
                packageVisibilityReviewAcknowledged = packageVisibilityReviewAcknowledged,
                onAcknowledgePackageVisibility = onAcknowledgePackageVisibility,
            ),
        )
    }
    val resolvedCount = cards.count { !it.requiresAction }
    val totalCount = cards.size.coerceAtLeast(1)
    val progress = resolvedCount.toFloat() / totalCount.toFloat()

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 18.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            StartupPolicyHero(
                gateState = gateState,
                resolvedCount = resolvedCount,
                totalCount = totalCount,
                progress = progress,
            )

            if (gateState == StartupGateState.LOADING) {
                LoadingPolicyCard()
            } else {
                cards.forEach { card ->
                    StartupPolicyCard(card = card)
                }
            }
        }
    }
}

@Composable
private fun StartupPolicyHero(
    gateState: StartupGateState,
    resolvedCount: Int,
    totalCount: Int,
    progress: Float,
) {
    Surface(
        shape = ShapeTokens.CornerExtraLargeIncreased,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(60.dp)
                        .background(
                            color = MaterialTheme.colorScheme.primaryContainer,
                            shape = CircleShape,
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = Icons.Rounded.VerifiedUser,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.size(28.dp),
                    )
                }

                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    WrapSafeText(
                        text = stringResource(R.string.startup_review_label),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                    )
                    WrapSafeText(
                        text = if (gateState == StartupGateState.LOADING) {
                            stringResource(R.string.startup_preparing_title)
                        } else {
                            stringResource(R.string.startup_before_scan_title)
                        },
                        style = MaterialTheme.typography.headlineSmall,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }

            WrapSafeText(
                text = if (gateState == StartupGateState.LOADING) {
                    stringResource(R.string.startup_loading_detail)
                } else {
                    stringResource(R.string.startup_intro_detail)
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            LinearProgressIndicator(
                progress = { progress },
                modifier = Modifier.fillMaxWidth(),
            )

            WrapSafeText(
                text = if (gateState == StartupGateState.LOADING) {
                    stringResource(R.string.startup_loading_state)
                } else {
                    stringResource(
                        R.string.startup_progress_resolved,
                        resolvedCount,
                        totalCount,
                    )
                },
                style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Medium),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun LoadingPolicyCard() {
    Surface(
        shape = ShapeTokens.CornerExtraLarge,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 18.dp, vertical = 18.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            CircularProgressIndicator(
                modifier = Modifier.size(28.dp),
                strokeWidth = 3.dp,
            )
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                WrapSafeText(
                    text = stringResource(R.string.startup_loading_dependencies_title),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                WrapSafeText(
                    text = stringResource(R.string.startup_loading_dependencies_detail),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
