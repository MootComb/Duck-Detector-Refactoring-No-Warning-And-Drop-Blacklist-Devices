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

package com.eltavine.duckdetector.features.dangerousapps.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.core.scan.DetectorSummary
import com.eltavine.duckdetector.core.scan.ScanSessionRunner
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsCatalog
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsReport
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsScanner
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsStage
import com.eltavine.duckdetector.features.dangerousapps.presentation.DangerousAppsCardModelMapper
import com.eltavine.duckdetector.features.dangerousapps.presentation.DangerousAppsUiStage
import com.eltavine.duckdetector.features.dangerousapps.presentation.DangerousAppsUiState
import com.eltavine.duckdetector.features.dangerousapps.presentation.toDetectorSummary
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update

class DangerousAppsViewModel(
    private val repository: DangerousAppsScanner,
    private val mapper: DangerousAppsCardModelMapper = DangerousAppsCardModelMapper(),
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        DangerousAppsUiState(
            stage = DangerousAppsUiStage.LOADING,
            report = DangerousAppsReport.loading(DangerousAppsCatalog.targets),
            cardModel = mapper.map(DangerousAppsReport.loading(DangerousAppsCatalog.targets)),
        ),
    )
    val uiState: StateFlow<DangerousAppsUiState> = _uiState.asStateFlow()

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
                val loading = DangerousAppsReport.loading(DangerousAppsCatalog.targets)
                _uiState.update {
                    it.copy(
                        stage = DangerousAppsUiStage.LOADING,
                        report = loading,
                        cardModel = mapper.map(loading),
                    )
                }
            },
            collect = { repository.scan() },
            publish = { report ->
                _uiState.update {
                    it.copy(
                        stage = if (report.stage == DangerousAppsStage.FAILED) {
                            DangerousAppsUiStage.FAILED
                        } else {
                            DangerousAppsUiStage.READY
                        },
                        report = report,
                        cardModel = mapper.map(report),
                    )
                }
            },
        )
    }

    companion object {
        fun factory(createScanner: () -> DangerousAppsScanner): ViewModelProvider.Factory {
            return object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return DangerousAppsViewModel(createScanner()) as T
                }
            }
        }
    }
}
