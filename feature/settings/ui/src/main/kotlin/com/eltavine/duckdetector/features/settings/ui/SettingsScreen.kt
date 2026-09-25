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

package com.eltavine.duckdetector.features.settings.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.features.settings.ui.R
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.features.settings.ui.licenses.OpenSourceLicensesEntry
import com.eltavine.duckdetector.features.settings.ui.licenses.OpenSourceLicensesScreen
import com.eltavine.duckdetector.features.settings.ui.components.AboutCard
import com.eltavine.duckdetector.features.settings.ui.components.AuthorCard
import com.eltavine.duckdetector.features.settings.ui.components.ConsentSettingCard
import com.eltavine.duckdetector.features.settings.presentation.model.SettingsUiState

@Composable
fun SettingsScreen(
    uiState: SettingsUiState,
    consentToggles: List<ConsentToggle>,
    onCheckForUpdates: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showingLicenses by rememberSaveable { mutableStateOf(false) }

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
    ) {
        if (showingLicenses) {
            OpenSourceLicensesScreen(
                onBack = { showingLicenses = false },
                modifier = Modifier.fillMaxSize(),
            )
        } else {
            Column(
                modifier = Modifier
                    .align(Alignment.TopCenter)
                    .widthIn(max = 720.dp)
                    .fillMaxWidth()
                    .statusBarsPadding()
                    .navigationBarsPadding()
                    .padding(horizontal = 20.dp, vertical = 20.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    WrapSafeText(
                        text = stringResource(R.string.settings_title),
                        style = MaterialTheme.typography.headlineMedium.copy(
                            fontWeight = FontWeight.Bold,
                        ),
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    WrapSafeText(
                        text = stringResource(R.string.settings_subtitle),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }

                consentToggles.forEach { toggle ->
                    ConsentSettingCard(toggle = toggle)
                }

                AboutCard(
                    versionName = uiState.versionName,
                    versionCode = uiState.versionCode,
                    buildTimeUtc = uiState.buildTimeUtc,
                    buildHash = uiState.buildHash,
                    updateStatus = uiState.updateStatus,
                    onCheckForUpdates = onCheckForUpdates,
                )

                OpenSourceLicensesEntry(
                    onClick = { showingLicenses = true },
                )

                AuthorCard()

                Spacer(modifier = Modifier.height(72.dp))
            }
        }
    }
}
