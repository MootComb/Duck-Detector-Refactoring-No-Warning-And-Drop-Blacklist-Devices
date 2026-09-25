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

package com.eltavine.duckdetector.features.systemproperties.ui

import android.content.Context
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.viewmodel.compose.viewModel
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.core.scan.DetectorSummary
import com.eltavine.duckdetector.core.ui.detector.DetectorFeature
import com.eltavine.duckdetector.core.ui.detector.DetectorSession
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesReport
import com.eltavine.duckdetector.features.systemproperties.presentation.SystemPropertiesDetectorId
import com.eltavine.duckdetector.features.systemproperties.presentation.toDetectorReport
import com.eltavine.duckdetector.features.systemproperties.ui.card.SystemPropertiesDetectorCard
import kotlinx.coroutines.flow.StateFlow

class SystemPropertiesDetectorFeature(
    private val createScanner: (Context) -> DetectorScanner<SystemPropertiesReport>,
) : DetectorFeature {
    override val id: DetectorId = SystemPropertiesDetectorId

    @Composable
    override fun rememberSession(): DetectorSession {
        val context = LocalContext.current
        val viewModel: SystemPropertiesViewModel = viewModel(
            factory = remember(context) { SystemPropertiesViewModel.factory { createScanner(context.applicationContext) } },
        )
        return remember(viewModel) { SystemPropertiesDetectorSession(viewModel) }
    }
}

private class SystemPropertiesDetectorSession(
    private val viewModel: SystemPropertiesViewModel,
) : DetectorSession {
    override val id: DetectorId = SystemPropertiesDetectorId

    override val summary: StateFlow<DetectorSummary> = viewModel.summary

    override fun report(): DetectorReport = viewModel.uiState.value.cardModel.toDetectorReport()

    override fun rescan() {
        viewModel.rescan()
    }

    @Composable
    override fun Card() {
        val state by viewModel.uiState.collectAsState()
        SystemPropertiesDetectorCard(model = state.cardModel)
    }
}
