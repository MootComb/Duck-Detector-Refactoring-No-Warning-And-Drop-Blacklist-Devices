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

/**
 * Marks a detector's own typed object, such as `SuDetector`. Its name and its report and card model
 * types follow that detector and may change in any release, unlike the [Detector] contract and
 * `DetectorResult`, whose public API dumps guard every change.
 *
 * A host that only needs results reaches every detector through `DuckDetector` and never opts in.
 * A host that uses one detector's typed models opts in, accepting that they change with it.
 */
@RequiresOptIn(
    message = "A detector's typed object and its report and card model types change with that detector in any release; DuckDetector and the Detector contract do not.",
    level = RequiresOptIn.Level.ERROR,
)
@Retention(AnnotationRetention.BINARY)
@Target(AnnotationTarget.CLASS)
public annotation class DetectorSpecificApi
