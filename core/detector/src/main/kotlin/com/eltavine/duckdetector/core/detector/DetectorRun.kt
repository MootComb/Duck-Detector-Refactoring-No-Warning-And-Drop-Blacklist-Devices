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

package com.eltavine.duckdetector.core.detector

import android.content.Context
import com.eltavine.duckdetector.core.report.DetectorHeadline
import com.eltavine.duckdetector.core.report.DetectorResult

/**
 * Scans once with a fresh scanner and returns the verdict and the export, without any UI.
 *
 * The result is what the dashboard would show and export for the same report: the status comes
 * from the card model's headline and the report from the same export projection.
 */
public suspend fun <R : Any, M : DetectorHeadline> Detector<R, M>.run(context: Context): DetectorResult {
    val model = describe(createScanner(context).scan())
    return DetectorResult(id = id, status = model.status, report = export(model))
}
