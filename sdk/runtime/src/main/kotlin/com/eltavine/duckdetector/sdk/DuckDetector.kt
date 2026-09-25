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

package com.eltavine.duckdetector.sdk

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.view.View
import android.webkit.WebView
import com.eltavine.duckdetector.capability.earlypreload.data.EarlyMountPreloadStore
import com.eltavine.duckdetector.capability.earlypreload.data.EarlyVirtualizationPreloadStore
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.run
import com.eltavine.duckdetector.core.report.DetectorResult
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.launch

/**
 * Runs Duck Detector's detectors without any UI.
 *
 * Each detector collects on-device evidence and returns a [DetectorResult]: its verdict and the
 * structured report the application exports for the same evidence. Results are diagnostic
 * evidence; they do not state that a device is secure or compromised.
 */
public object DuckDetector {
    /** Every detector, in the order [scan] starts them. */
    public val detectors: List<Detector<*, *>>
        get() = DetectorCatalog.all

    /**
     * Runs every detector once and returns the results in [detectors] order.
     *
     * The scans run concurrently, as they do in the application; each detector moves its own
     * collection off the calling dispatcher.
     */
    public suspend fun scan(context: Context): List<DetectorResult> = coroutineScope {
        val application = context.applicationContext
        detectors.map { detector -> async { detector.run(application) } }.awaitAll()
    }

    /** Runs every detector once and emits each result as soon as that detector finishes. */
    public fun results(context: Context): Flow<DetectorResult> = channelFlow {
        val application = context.applicationContext
        detectors.forEach { detector -> launch { send(detector.run(application)) } }
    }

    /**
     * Keeps the early mount and virtualization evidence that the transparent `NativeActivity`
     * captured before the first activity and passed on in [intent].
     *
     * Call it from the receiving activity's `onCreate` and `onNewIntent`. Without that launch, the
     * Mount and Virtualization detectors report the early capture as unavailable.
     */
    public fun captureLaunchEvidence(intent: Intent?) {
        EarlyMountPreloadStore.capture(intent)
        EarlyVirtualizationPreloadStore.capture(intent)
    }

    /**
     * Creates the invisible 1x1 WebView an activity attaches before its UI starts, or null when
     * WebView is unavailable.
     *
     * The application attaches it before binding any helper process, matching the WebView-before-
     * bind order of PrivIsolated, from which the isolated mount-view scanner is ported. Destroy it
     * with the activity.
     */
    public fun createProcMountSampler(context: Context): WebView? = runCatching {
        WebView(context).apply {
            alpha = 0f
            isClickable = false
            isFocusable = false
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
            setBackgroundColor(Color.TRANSPARENT)
            loadDataWithBaseURL(
                null,
                "<html><body></body></html>",
                "text/html",
                Charsets.UTF_8.name(),
                null,
            )
        }
    }.getOrNull()
}
