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

package com.eltavine.duckdetector.features.dashboard.ui

import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.LoadingIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.components.StatusBarProtection
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import com.eltavine.duckdetector.core.ui.detector.DetectorSession
import com.eltavine.duckdetector.core.ui.detector.DeviceProfileSession
import com.eltavine.duckdetector.core.ui.LocalAppBuildInfo
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.presentation.formatBuildTimeUtc
import com.eltavine.duckdetector.features.dashboard.presentation.export.DashboardExport
import com.eltavine.duckdetector.features.dashboard.presentation.export.DashboardReportRenderer
import com.eltavine.duckdetector.features.dashboard.presentation.export.ExportHeader
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardFindingModel
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardOverviewModel
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardUiState
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

@Composable
fun DashboardScreen(
    uiState: DashboardUiState,
    detectors: List<DetectorSession>,
    deviceProfile: DeviceProfileSession,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val buildInfo = LocalAppBuildInfo.current
    val orderedDetectors = remember(uiState.cardOrder, detectors) {
        val detectorsById = detectors.associateBy { it.id }
        uiState.cardOrder.mapNotNull { detectorsById[it] }
    }
    val exportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri ->
        if (uri != null) {
            try {
                val text = DashboardReportRenderer.render(
                    DashboardExport(
                        header = ExportHeader(
                            versionName = buildInfo.versionName,
                            versionCode = buildInfo.versionCode,
                            buildHash = buildInfo.buildHash,
                            buildTime = formatBuildTimeUtc(buildInfo.buildTimeUtc),
                            reportTime = SimpleDateFormat("yyyy-MM-dd HH:mm:ss (z)", Locale.US).format(Date()),
                        ),
                        overview = uiState.overview,
                        topFindings = uiState.topFindings,
                        detectors = orderedDetectors.map { it.report() },
                        device = deviceProfile.report(),
                    ),
                )
                context.contentResolver.openOutputStream(uri)?.use { stream ->
                    stream.write(text.toByteArray(Charsets.UTF_8))
                }
                Toast.makeText(
                    context,
                    "Report saved",
                    Toast.LENGTH_SHORT,
                ).show()
            } catch (e: Exception) {
                Toast.makeText(
                    context,
                    "Save failed: ${e.message}",
                    Toast.LENGTH_SHORT,
                ).show()
            }
        }
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(DuckTheme.palette.groupedBackground),
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            contentPadding = WindowInsets.safeDrawing
                // The bottom clears the floating tab switcher the shell draws over the last card.
                .add(WindowInsets(left = 16.dp, top = 12.dp, right = 16.dp, bottom = 96.dp))
                .asPaddingValues(),
        ) {
            item { BrandHeader() }
            item {
                ExportButton(
                    onClick = {
                        exportLauncher.launch(generateExportReportFileName())
                    },
                )
            }
            item {
                DashboardSummarySection(
                    overview = uiState.overview,
                    findings = uiState.topFindings,
                    showLoadingOverlay = uiState.isLoading,
                )
            }
            items(
                items = orderedDetectors,
                key = { detector -> detector.id.value },
            ) { detector ->
                detector.Card()
            }
            item {
                deviceProfile.Card()
            }
        }

        StatusBarProtection(modifier = Modifier.align(Alignment.TopCenter))
    }
}

@Composable
private fun DashboardSummarySection(
    overview: DashboardOverviewModel,
    findings: List<DashboardFindingModel>,
    showLoadingOverlay: Boolean,
) {
    Box(modifier = Modifier.fillMaxWidth()) {
        Column(verticalArrangement = Arrangement.spacedBy(24.dp)) {
            DashboardOverviewCard(model = overview)
            DashboardFindingsCard(findings = findings)
        }

        if (showLoadingOverlay) {
            DashboardLoadingOverlay(
                modifier = Modifier.matchParentSize(),
            )
        }
    }
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
private fun DashboardLoadingOverlay(
    modifier: Modifier = Modifier,
) {
    // The summary it covers is taller than the screen, so the message sits near its top edge.
    Box(
        modifier = modifier.background(
            color = DuckTheme.palette.groupedSurface,
            shape = ShapeTokens.CornerExtraLargeIncreased,
        ),
        contentAlignment = Alignment.TopCenter,
    ) {
        Column(
            modifier = Modifier.padding(start = 32.dp, end = 32.dp, top = 88.dp, bottom = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            LoadingIndicator(modifier = Modifier.size(56.dp))
            WrapSafeText(
                text = "Running local checks",
                modifier = Modifier.padding(top = 6.dp),
                style = DuckTypography.Headline,
                color = MaterialTheme.colorScheme.onSurface,
                textAlign = TextAlign.Center,
            )
            WrapSafeText(
                text = "Dashboard summary will unlock when the detector cards finish collecting evidence.",
                style = DuckTypography.Footnote,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
    }
}

@Composable
private fun ExportButton(
    onClick: () -> Unit,
) {
    Button(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        shape = ShapeTokens.CornerLarge,
        colors = ButtonDefaults.buttonColors(
            containerColor = DuckTheme.palette.groupedSurface,
            contentColor = MaterialTheme.colorScheme.primary,
        ),
        contentPadding = PaddingValues(vertical = 15.dp),
    ) {
        Icon(
            imageVector = Icons.Rounded.FileDownload,
            contentDescription = null,
            modifier = Modifier.size(20.dp),
        )
        Spacer(modifier = Modifier.size(8.dp))
        WrapSafeText(
            text = "Export Report",
            style = DuckTypography.Headline,
        )
    }
}

internal fun generateExportReportFileName(
    model: String = Build.MODEL,
    nowEpochMillis: Long = System.currentTimeMillis(),
): String {
    val sanitizedModel = model.trim().ifBlank { "unknown" }
        .replace(Regex("[^a-zA-Z0-9._-]"), "_")
    // Filenames are machine-readable and must not vary with the device language/locale.
    val timestampFormat = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.ROOT).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }
    val timestamp = timestampFormat.format(Date(nowEpochMillis))
    return "duck_detector_report_${sanitizedModel}_$timestamp.txt"
}
