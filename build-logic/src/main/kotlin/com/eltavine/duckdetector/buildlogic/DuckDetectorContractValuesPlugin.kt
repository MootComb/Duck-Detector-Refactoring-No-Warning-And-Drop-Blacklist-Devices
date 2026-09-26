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

package com.eltavine.duckdetector.buildlogic

import dev.drewhamilton.poko.gradle.PokoPluginExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.configure

/**
 * Lets a contract module declare value types with `@ContractValue`. Poko generates their `equals`,
 * `hashCode` and `toString` as for a data class, but no `copy` or `componentN`, so adding a property
 * does not change a signature that SDK hosts compiled against.
 */
class DuckDetectorContractValuesPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            pluginManager.apply("dev.drewhamilton.poko")
            extensions.configure<PokoPluginExtension> {
                pokoAnnotation.set("com/eltavine/duckdetector/core/evidence/ContractValue")
            }
        }
    }
}
