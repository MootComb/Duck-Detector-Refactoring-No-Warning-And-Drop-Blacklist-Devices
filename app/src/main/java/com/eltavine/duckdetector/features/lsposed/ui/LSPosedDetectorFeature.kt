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

package com.eltavine.duckdetector.features.lsposed.ui

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
import com.eltavine.duckdetector.features.lsposed.presentation.LSPosedDetectorId
import com.eltavine.duckdetector.features.lsposed.presentation.LSPosedViewModel
import com.eltavine.duckdetector.features.lsposed.presentation.toDetectorReport
import com.eltavine.duckdetector.features.lsposed.ui.card.LSPosedDetectorCard
import kotlinx.coroutines.flow.StateFlow

object LSPosedDetectorFeature : DetectorFeature {
    override val id: DetectorId = LSPosedDetectorId

    @Composable
    override fun rememberSession(): DetectorSession {
        val context = LocalContext.current
        val viewModel: LSPosedViewModel = viewModel(factory = remember(context) { LSPosedViewModel.factory(context) })
        return remember(viewModel) { LSPosedDetectorSession(viewModel) }
    }
}

private class LSPosedDetectorSession(
    private val viewModel: LSPosedViewModel,
) : DetectorSession {
    override val id: DetectorId = LSPosedDetectorId

    override val summary: StateFlow<DetectorSummary> = viewModel.summary

    override fun report(): DetectorReport = viewModel.uiState.value.cardModel.toDetectorReport()

    override fun rescan() {
        viewModel.rescan()
    }

    @Composable
    override fun Card() {
        val state by viewModel.uiState.collectAsState()
        LSPosedDetectorCard(model = state.cardModel)
    }
}
