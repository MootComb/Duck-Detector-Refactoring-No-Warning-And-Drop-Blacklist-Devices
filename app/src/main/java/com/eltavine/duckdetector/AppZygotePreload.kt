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

package com.eltavine.duckdetector

import android.app.ZygotePreload
import com.eltavine.duckdetector.sdk.DuckDetectorZygotePreload

/** The class the manifest names in android:zygotePreloadName; the SDK owns the detection work it runs. */
class AppZygotePreload : ZygotePreload by DuckDetectorZygotePreload()
