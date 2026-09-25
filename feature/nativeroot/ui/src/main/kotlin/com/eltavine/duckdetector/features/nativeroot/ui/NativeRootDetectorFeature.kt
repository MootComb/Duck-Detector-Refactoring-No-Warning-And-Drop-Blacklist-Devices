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

package com.eltavine.duckdetector.features.nativeroot.ui

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
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.presentation.NativeRootDetectorId
import com.eltavine.duckdetector.features.nativeroot.presentation.toDetectorReport
import com.eltavine.duckdetector.features.nativeroot.ui.card.NativeRootDetectorCard
import kotlinx.coroutines.flow.StateFlow

class NativeRootDetectorFeature(
    private val createScanner: (Context) -> DetectorScanner<NativeRootReport>,
) : DetectorFeature {
    override val id: DetectorId = NativeRootDetectorId

    @Composable
    override fun rememberSession(): DetectorSession {
        val context = LocalContext.current
        val viewModel: NativeRootViewModel = viewModel(
            factory = remember(context) { NativeRootViewModel.factory { createScanner(context.applicationContext) } },
        )
        return remember(viewModel) { NativeRootDetectorSession(viewModel) }
    }
}

private class NativeRootDetectorSession(
    private val viewModel: NativeRootViewModel,
) : DetectorSession {
    override val id: DetectorId = NativeRootDetectorId

    override val summary: StateFlow<DetectorSummary> = viewModel.summary

    override fun report(): DetectorReport = viewModel.uiState.value.cardModel.toDetectorReport()

    override fun rescan() {
        viewModel.rescan()
    }

    @Composable
    override fun Card() {
        val state by viewModel.uiState.collectAsState()
        NativeRootDetectorCard(model = state.cardModel)
    }
}
