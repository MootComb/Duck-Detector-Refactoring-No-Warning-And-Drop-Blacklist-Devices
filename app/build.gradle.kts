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

import com.eltavine.duckdetector.buildlogic.detectorModules

plugins {
    id("duckdetector.android.application")
    id("duckdetector.android.apk-artifacts")
}

android {
    namespace = "com.eltavine.duckdetector"

    defaultConfig {
        applicationId = "com.eltavine.duckdetector"
    }
}

dependencies {
    implementation(project(":capability:earlypreload:data"))
    implementation(project(":capability:packageinventory:data"))
    implementation(project(":capability:selinuxpolicy:data"))
    implementation(project(":core:evidence"))
    implementation(project(":core:report"))
    implementation(project(":core:scan"))
    implementation(project(":core:ui"))
    implementation(project(":feature:dashboard:ui"))
    implementation(project(":feature:deviceinfo:data"))
    implementation(project(":feature:deviceinfo:ui"))
    implementation(project(":feature:nativeroot:data"))
    implementation(project(":feature:settings:ui"))
    implementation(project(":feature:tee:data"))
    implementation(project(":feature:update:data"))
    implementation(project(":feature:update:ui"))
    implementation(project(":sdk:runtime"))
    // Every detector's dashboard card, discovered like the SDK discovers the detectors.
    detectorModules("ui").forEach { implementation(project(it)) }
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.bundles.app.runtime)
    implementation(libs.bundles.app.compose)
    implementation(libs.bundles.app.security)
    testImplementation(libs.bundles.test.unit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.bundles.test.android)
    debugImplementation(libs.androidx.ui.tooling)
}
