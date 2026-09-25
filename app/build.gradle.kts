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
    implementation(project(":capability:systemproperties:data"))
    implementation(project(":capability:earlypreload:data"))
    implementation(project(":capability:packageinventory:data"))
    implementation(project(":core:detector"))
    implementation(project(":core:evidence"))
    implementation(project(":core:native"))
    implementation(project(":core:report"))
    implementation(project(":core:scan"))
    implementation(project(":core:ui"))
    implementation(project(":feature:su:data"))
    implementation(project(":feature:su:ui"))
    implementation(project(":feature:memory:data"))
    implementation(project(":feature:memory:ui"))
    implementation(project(":feature:kernelcheck:data"))
    implementation(project(":feature:kernelcheck:ui"))
    implementation(project(":feature:playintegrityfix:data"))
    implementation(project(":feature:playintegrityfix:ui"))
    implementation(project(":feature:zygisk:data"))
    implementation(project(":feature:zygisk:ui"))
    implementation(project(":feature:customrom:data"))
    implementation(project(":feature:customrom:ui"))
    implementation(project(":feature:dangerousapps:data"))
    implementation(project(":feature:dangerousapps:ui"))
    implementation(project(":feature:systemproperties:data"))
    implementation(project(":feature:systemproperties:ui"))
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.bundles.app.runtime)
    implementation(libs.bundles.app.compose)
    implementation(libs.aboutlibraries.compose.m3) {
        exclude(group = "com.github.skydoves", module = "compose-stability-runtime")
    }
    implementation(libs.bundles.app.security)
    testImplementation(libs.bundles.test.unit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.bundles.test.android)
    debugImplementation(libs.androidx.ui.tooling)
}
