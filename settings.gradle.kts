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

pluginManagement {
    includeBuild("build-logic")
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven(url = "https://jitpack.io")
    }
}

rootProject.name = "Duck Detector"
include(":app")
include(":capability:packageinventory:data")
include(":capability:packageinventory:domain")
include(":core:detector")
include(":core:evidence")
include(":core:native")
include(":core:report")
include(":core:scan")
include(":core:ui")
 
include(":feature:su:domain")
include(":feature:su:data")
include(":feature:su:presentation")
include(":feature:su:ui")
include(":feature:memory:domain")
include(":feature:memory:data")
include(":feature:memory:presentation")
include(":feature:memory:ui")
include(":feature:kernelcheck:domain")
include(":feature:kernelcheck:data")
include(":feature:kernelcheck:presentation")
include(":feature:kernelcheck:ui")
include(":feature:playintegrityfix:domain")
include(":feature:playintegrityfix:data")
include(":feature:playintegrityfix:presentation")
include(":feature:playintegrityfix:ui")
include(":feature:zygisk:domain")
include(":feature:zygisk:data")
include(":feature:zygisk:presentation")
include(":feature:zygisk:ui")
include(":capability:earlypreload:data")
include(":feature:customrom:domain")
include(":feature:customrom:data")
include(":feature:customrom:presentation")
include(":feature:customrom:ui")
