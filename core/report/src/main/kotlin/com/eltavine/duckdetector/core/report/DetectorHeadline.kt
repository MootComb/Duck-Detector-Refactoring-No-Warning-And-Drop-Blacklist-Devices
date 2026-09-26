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

package com.eltavine.duckdetector.core.report

import com.eltavine.duckdetector.core.evidence.DetectorStatus

/**
 * What the top of a detector's card states. The dashboard summarizes a detector from it, and a
 * headless run takes the detector's verdict from [status].
 */
public interface DetectorHeadline {
    public val title: String

    /** The detector's verdict on the described report. */
    public val status: DetectorStatus

    public val verdict: String

    public val summary: String

    /** Shorter text for the dashboard's top findings; the card keeps its full detail. */
    public val findingDetail: String?
        get() = null
}
