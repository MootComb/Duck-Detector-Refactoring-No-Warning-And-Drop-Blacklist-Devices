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

// The SDK is compiled with Kotlin 2.4, whose metadata the Kotlin that AGP bundles cannot read, so the
// consumer puts the same Kotlin Gradle plugin on its classpath.
buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath(libs.kotlin.gradle.plugin)
    }
}

plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.eltavine.duckdetector.sample"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.eltavine.duckdetector.sample"
        minSdk = 29
        targetSdk = 37
    }
}

dependencies {
    implementation("com.eltavine.duckdetector:duckdetector-sdk:0.0.0-SNAPSHOT")
}
