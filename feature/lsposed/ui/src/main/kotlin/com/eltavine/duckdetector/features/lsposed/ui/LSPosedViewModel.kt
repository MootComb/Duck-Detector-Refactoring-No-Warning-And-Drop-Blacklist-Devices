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

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.core.scan.DetectorSummary
import com.eltavine.duckdetector.core.scan.ScanSessionRunner
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedReport
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedScanner
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedStage
import com.eltavine.duckdetector.features.lsposed.presentation.LSPosedCardModelMapper
import com.eltavine.duckdetector.features.lsposed.presentation.LSPosedUiStage
import com.eltavine.duckdetector.features.lsposed.presentation.LSPosedUiState
import com.eltavine.duckdetector.features.lsposed.presentation.toDetectorSummary
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update

class LSPosedViewModel(
    private val repository: LSPosedScanner,
    private val mapper: LSPosedCardModelMapper = LSPosedCardModelMapper(),
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        LSPosedUiState(
            stage = LSPosedUiStage.LOADING,
            report = LSPosedReport.loading(),
            cardModel = mapper.map(LSPosedReport.loading()),
        ),
    )
    val uiState: StateFlow<LSPosedUiState> = _uiState.asStateFlow()

    val summary: StateFlow<DetectorSummary> = uiState
        .map { it.toDetectorSummary() }
        .stateIn(viewModelScope, SharingStarted.Eagerly, uiState.value.toDetectorSummary())

    private val scans = ScanSessionRunner(viewModelScope)

    init {
        rescan()
    }

    fun rescan() {
        scans.launch(
            begin = {
                val loading = LSPosedReport.loading()
                _uiState.update {
                    it.copy(
                        stage = LSPosedUiStage.LOADING,
                        report = loading,
                        cardModel = mapper.map(loading),
                    )
                }
            },
            collect = { repository.scan() },
            publish = { report ->
                _uiState.update {
                    it.copy(
                        stage = if (report.stage == LSPosedStage.FAILED) {
                            LSPosedUiStage.FAILED
                        } else {
                            LSPosedUiStage.READY
                        },
                        report = report,
                        cardModel = mapper.map(report),
                    )
                }
            },
        )
    }

    companion object {
        fun factory(createScanner: () -> LSPosedScanner): ViewModelProvider.Factory {
            return object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return LSPosedViewModel(createScanner()) as T
                }
            }
        }
    }
}
