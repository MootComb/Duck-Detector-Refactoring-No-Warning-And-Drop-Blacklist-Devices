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

import com.eltavine.duckdetector.buildlogic.DETECTOR_LAYER
import com.eltavine.duckdetector.buildlogic.detectorModules

plugins {
    id("duckdetector.android.library")
    id("duckdetector.public-api")
    id("duckdetector.contract-values")
}

android {
    namespace = "com.eltavine.duckdetector.sdk"
}

kotlin {
    explicitApi()
}

dependencies {
    implementation(project(":capability:earlypreload:data"))
    implementation(project(":capability:packageinventory:data"))
    implementation(project(":capability:packageinventory:domain"))
    implementation(project(":capability:selinuxpolicy:data"))
    implementation(project(":core:evidence"))
    api(project(":core:detector"))
    api(project(":core:report"))
    // Every detector unit, discovered from its directory, so the catalog and the AAR can hold all of them.
    detectorModules(DETECTOR_LAYER).forEach { implementation(project(it)) }
    api(libs.kotlinx.coroutines.core)
}
