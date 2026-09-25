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

package com.eltavine.duckdetector.features.tee.ui

import android.content.Context
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.viewmodel.compose.viewModel
import com.eltavine.duckdetector.core.detector.DetectorFeature
import com.eltavine.duckdetector.core.detector.DetectorSession
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.core.scan.DetectorSummary
import com.eltavine.duckdetector.features.tee.domain.TeeScanner
import com.eltavine.duckdetector.features.tee.presentation.TeeDetectorId
import com.eltavine.duckdetector.features.tee.presentation.toDetectorReport
import com.eltavine.duckdetector.features.tee.ui.card.TeeDetectorCard
import kotlinx.coroutines.flow.StateFlow

class TeeDetectorFeature(
    private val createScanner: (Context) -> TeeScanner,
) : DetectorFeature {
    override val id: DetectorId = TeeDetectorId

    @Composable
    override fun rememberSession(): DetectorSession {
        val context = LocalContext.current
        val viewModel: TeeViewModel = viewModel(
            factory = remember(context) { TeeViewModel.factory { createScanner(context.applicationContext) } },
        )
        return remember(viewModel) { TeeDetectorSession(viewModel) }
    }
}

private class TeeDetectorSession(
    private val viewModel: TeeViewModel,
) : DetectorSession {
    override val id: DetectorId = TeeDetectorId

    override val summary: StateFlow<DetectorSummary> = viewModel.summary

    override fun report(): DetectorReport = viewModel.uiState.value.cardModel.toDetectorReport()

    override fun rescan() {
        viewModel.rescan()
    }

    @Composable
    override fun Card() {
        val state by viewModel.uiState.collectAsState()
        TeeDetectorCard(
            model = state.cardModel,
            showDetailsDialog = state.showDetailsDialog,
            showCertificatesDialog = state.showCertificatesDialog,
            onExpandedChange = viewModel::onExpandedChange,
            onFooterAction = viewModel::onFooterAction,
            onDismissDetails = viewModel::dismissDetails,
            onDismissCertificates = viewModel::dismissCertificates,
        )
    }
}
