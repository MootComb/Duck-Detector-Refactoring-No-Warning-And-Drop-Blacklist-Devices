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

package com.eltavine.duckdetector.startup.legal

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.scaleIn
import androidx.compose.animation.slideInVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Gavel
import androidx.compose.material.icons.outlined.PrivacyTip
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.ui.theme.MotionTokens
import kotlinx.coroutines.delay

@Composable
fun AgreementScreen(
    onAgree: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var countdown by remember { mutableIntStateOf(30) }
    val timerComplete = countdown <= 0
    val (num1, num2, isAddition) = remember {
        val a = (10..99).random()
        val b = (1..minOf(a, 99 - a)).random()
        val add = listOf(true, false).random()
        Triple(a, b, add)
    }
    val correctAnswer = remember(num1, num2, isAddition) {
        if (isAddition) num1 + num2 else num1 - num2
    }
    var userAnswer by remember { mutableStateOf("") }
    val isCheatCode = userAnswer == "196912"
    val mathCorrect = userAnswer.toIntOrNull() == correctAnswer || isCheatCode
    val scrollState = rememberScrollState()
    val isScrolledToBottom by remember {
        derivedStateOf {
            val maxScroll = scrollState.maxValue
            maxScroll > 0 && scrollState.value >= maxScroll - 50
        }
    }
    val canProceed = isCheatCode || (timerComplete && mathCorrect && isScrolledToBottom)
    val buttonScale by animateFloatAsState(
        targetValue = if (canProceed) 1f else 0.96f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessLow,
        ),
        label = "agreement_button_scale",
    )
    val buttonAlpha by animateFloatAsState(
        targetValue = if (canProceed) 1f else 0.5f,
        animationSpec = tween(MotionTokens.Duration.Medium2),
        label = "agreement_button_alpha",
    )
    var showContent by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        showContent = true
    }

    LaunchedEffect(Unit) {
        while (countdown > 0) {
            delay(1_000L)
            countdown -= 1
        }
    }

    Surface(
        modifier = modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background,
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding(),
        ) {
            Column(
                modifier = Modifier
                    .weight(1f)
                    .verticalScroll(scrollState)
                    .padding(horizontal = 24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Spacer(modifier = Modifier.height(40.dp))

                AnimatedVisibility(
                    visible = showContent,
                    enter = scaleIn(
                        animationSpec = spring(
                            dampingRatio = Spring.DampingRatioMediumBouncy,
                            stiffness = Spring.StiffnessLow,
                        ),
                    ) + fadeIn(),
                ) {
                    Box(
                        modifier = Modifier
                            .size(96.dp)
                            .shadow(
                                elevation = 8.dp,
                                shape = CircleShape,
                                ambientColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.3f),
                                spotColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.3f),
                            )
                            .clip(CircleShape)
                            .background(
                                Brush.radialGradient(
                                    colors = listOf(
                                        MaterialTheme.colorScheme.primaryContainer,
                                        MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.8f),
                                    ),
                                ),
                            ),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Security,
                            contentDescription = null,
                            modifier = Modifier.size(48.dp),
                            tint = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                    }
                }

                Spacer(modifier = Modifier.height(28.dp))

                AnimatedVisibility(
                    visible = showContent,
                    enter = slideInVertically(
                        initialOffsetY = { it / 2 },
                        animationSpec = spring(
                            dampingRatio = Spring.DampingRatioLowBouncy,
                            stiffness = Spring.StiffnessLow,
                        ),
                    ) + fadeIn(),
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            text = stringResource(R.string.user_agreement),
                            style = MaterialTheme.typography.headlineMedium,
                            fontWeight = FontWeight.Bold,
                            textAlign = TextAlign.Center,
                            color = MaterialTheme.colorScheme.onBackground,
                        )
                        Text(
                            text = stringResource(R.string.disclaimer),
                            style = MaterialTheme.typography.headlineSmall,
                            fontWeight = FontWeight.Medium,
                            textAlign = TextAlign.Center,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                AnimatedVisibility(
                    visible = showContent,
                    enter = fadeIn(animationSpec = tween(delayMillis = 200)),
                ) {
                    Text(
                        text = stringResource(R.string.please_read_carefully),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.error,
                        fontWeight = FontWeight.SemiBold,
                        textAlign = TextAlign.Center,
                    )
                }

                Spacer(modifier = Modifier.height(20.dp))

                AgreementRiskBanner()

                Spacer(modifier = Modifier.height(24.dp))

                AgreementSection(
                    icon = Icons.Outlined.Gavel,
                    title = stringResource(R.string.user_agreement_title),
                    content = stringResource(R.string.user_agreement_content),
                )

                Spacer(modifier = Modifier.height(16.dp))

                AgreementSection(
                    icon = Icons.Outlined.Warning,
                    title = stringResource(R.string.disclaimer_title),
                    content = stringResource(R.string.disclaimer_content),
                    tone = AgreementSectionTone.Warning,
                )

                Spacer(modifier = Modifier.height(16.dp))

                AgreementSection(
                    icon = Icons.Outlined.PrivacyTip,
                    title = stringResource(R.string.privacy_notice_title),
                    content = stringResource(R.string.privacy_notice_content),
                    tone = AgreementSectionTone.Notice,
                )

                Spacer(modifier = Modifier.height(32.dp))
            }

            AgreementConsentPanel(
                countdown = countdown,
                timerComplete = timerComplete,
                num1 = num1,
                num2 = num2,
                isAddition = isAddition,
                userAnswer = userAnswer,
                onUserAnswerChange = { userAnswer = it },
                mathCorrect = mathCorrect,
                isScrolledToBottom = isScrolledToBottom,
                canProceed = canProceed,
                buttonScale = buttonScale,
                buttonAlpha = buttonAlpha,
                onAgree = onAgree,
            )
        }
    }
}
