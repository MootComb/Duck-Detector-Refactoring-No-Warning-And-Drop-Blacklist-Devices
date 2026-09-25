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
include(":feature:dangerousapps:domain")
include(":feature:dangerousapps:data")
include(":feature:dangerousapps:presentation")
include(":feature:dangerousapps:ui")
include(":capability:systemproperties:domain")
include(":capability:systemproperties:data")
include(":feature:systemproperties:domain")
include(":feature:systemproperties:data")
include(":feature:systemproperties:presentation")
include(":feature:systemproperties:ui")
include(":capability:helperprocess:data")
include(":feature:virtualization:domain")
include(":feature:virtualization:data")
include(":feature:virtualization:presentation")
include(":feature:virtualization:ui")
include(":feature:mount:domain")
include(":feature:mount:data")
include(":feature:mount:presentation")
include(":feature:mount:ui")
include(":capability:selinuxpolicy:data")
include(":feature:selinux:domain")
include(":feature:selinux:data")
include(":feature:selinux:presentation")
include(":feature:selinux:ui")
include(":feature:lsposed:domain")
include(":feature:lsposed:data")
include(":feature:lsposed:presentation")
include(":feature:lsposed:ui")
include(":feature:nativeroot:domain")
include(":feature:nativeroot:data")
include(":feature:nativeroot:presentation")
include(":feature:nativeroot:ui")
include(":capability:attestation:domain")
include(":capability:attestation:data")
include(":feature:bootloader:domain")
include(":feature:bootloader:data")
include(":feature:bootloader:presentation")
include(":feature:bootloader:ui")
include(":feature:tee:domain")
include(":feature:tee:data")
include(":feature:tee:presentation")
include(":feature:tee:ui")
include(":feature:deviceinfo:domain")
include(":feature:deviceinfo:data")
include(":feature:deviceinfo:presentation")
include(":feature:deviceinfo:ui")
