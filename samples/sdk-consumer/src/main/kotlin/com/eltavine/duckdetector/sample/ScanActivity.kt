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

package com.eltavine.duckdetector.sample

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.TextView
import com.eltavine.duckdetector.core.detector.DetectorSpecificApi
import com.eltavine.duckdetector.core.detector.run
import com.eltavine.duckdetector.core.report.DetectorResult
import com.eltavine.duckdetector.features.su.detector.SuDetector
import com.eltavine.duckdetector.sdk.DuckDetector
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Runs one detector, then every detector, through the SDK alone and lists each verdict. The SDK's
 * launcher starts it with the early launch evidence. Running SU through `SuDetector` opts in to
 * that detector's own API, which may change in any release.
 */
@OptIn(DetectorSpecificApi::class)
class ScanActivity : Activity() {

    private val scope = MainScope()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        DuckDetector.captureLaunchEvidence(intent)
        val output = TextView(this)
        setContentView(output)
        scope.launch {
            val su: DetectorResult = SuDetector.run(this@ScanActivity)
            val all: List<DetectorResult> = DuckDetector.scan(this@ScanActivity)
            output.text = (listOf(su) + all).joinToString(separator = "\n") { result ->
                "${result.id}: ${result.status.severity} (${result.report.verdict})"
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        DuckDetector.captureLaunchEvidence(intent)
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
