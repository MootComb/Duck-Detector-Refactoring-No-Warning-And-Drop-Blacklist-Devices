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

package com.eltavine.duckdetector.core.scan

import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.report.DetectorHeadline

/**
 * What one detector publishes about its current scan.
 *
 * This is the only view of a detector that scan coordination, the overview and notifications
 * need, so none of them depend on a detector's own report or UI state.
 */
public data class DetectorSummary(
    val id: DetectorId,
    val title: String,
    val status: DetectorStatus,
    val headline: String,
    val summary: String,
    val ready: Boolean,
    /** Optional shorter text for the overview's findings; the detector card keeps its full detail. */
    val findingDetail: String? = null,
)

/** The summary a detector publishes for a card stating this headline; [ready] once a scan has finished. */
public fun DetectorHeadline.summarize(id: DetectorId, ready: Boolean): DetectorSummary = DetectorSummary(
    id = id,
    title = title,
    status = status,
    headline = verdict,
    summary = summary,
    ready = ready,
    findingDetail = findingDetail,
)
