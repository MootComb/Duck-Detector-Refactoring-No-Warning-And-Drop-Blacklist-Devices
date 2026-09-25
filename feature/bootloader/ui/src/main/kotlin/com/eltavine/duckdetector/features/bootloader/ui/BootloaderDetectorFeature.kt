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

package com.eltavine.duckdetector.features.bootloader.ui

import com.eltavine.duckdetector.core.ui.detector.CardDetectorFeature
import com.eltavine.duckdetector.core.ui.detector.DetectorFeature
import com.eltavine.duckdetector.features.bootloader.detector.BootloaderDetector
import com.eltavine.duckdetector.features.bootloader.ui.card.BootloaderDetectorCard

/** The Bootloader card on the dashboard. */
val BootloaderDetectorFeature: DetectorFeature = CardDetectorFeature(BootloaderDetector) { model -> BootloaderDetectorCard(model = model) }
