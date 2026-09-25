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

package com.eltavine.duckdetector.features.mount.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.scan.DetectorSummary
import com.eltavine.duckdetector.core.scan.ScanSessionRunner
import com.eltavine.duckdetector.features.mount.domain.MountReport
import com.eltavine.duckdetector.features.mount.domain.MountStage
import com.eltavine.duckdetector.features.mount.presentation.MountCardModelMapper
import com.eltavine.duckdetector.features.mount.presentation.MountUiStage
import com.eltavine.duckdetector.features.mount.presentation.MountUiState
import com.eltavine.duckdetector.features.mount.presentation.toDetectorSummary
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update

class MountViewModel(
    private val repository: DetectorScanner<MountReport>,
    private val mapper: MountCardModelMapper = MountCardModelMapper(),
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        MountUiState(
            stage = MountUiStage.LOADING,
            report = MountReport.loading(),
            cardModel = mapper.map(MountReport.loading()),
        ),
    )
    val uiState: StateFlow<MountUiState> = _uiState.asStateFlow()

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
                val loading = MountReport.loading()
                _uiState.update {
                    it.copy(
                        stage = MountUiStage.LOADING,
                        report = loading,
                        cardModel = mapper.map(loading),
                    )
                }
            },
            collect = { repository.scan() },
            publish = { report ->
                val cardModel = mapper.map(report)
                _uiState.update {
                    it.copy(
                        stage = if (report.stage == MountStage.FAILED) {
                            MountUiStage.FAILED
                        } else {
                            MountUiStage.READY
                        },
                        report = report,
                        cardModel = cardModel,
                    )
                }
            },
        )
    }

    companion object {
        fun factory(createScanner: () -> DetectorScanner<MountReport>): ViewModelProvider.Factory {
            return object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return MountViewModel(createScanner()) as T
                }
            }
        }
    }
}
