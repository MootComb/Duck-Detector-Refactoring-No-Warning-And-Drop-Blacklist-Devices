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

package com.eltavine.duckdetector.buildlogic.api

import javax.inject.Inject
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Classpath
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.workers.WorkerExecutor

/** Fails when the module's public API differs from the reference dump committed under `api/`. */
abstract class CheckPublicApiTask : DefaultTask() {

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val actual: RegularFileProperty

    /** The committed dump; a collection so that a missing file reaches the task action. */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val reference: ConfigurableFileCollection

    @get:Input
    abstract val updateTask: Property<String>

    /** `org.jetbrains.kotlin:abi-tools` with its runtime classpath. */
    @get:Classpath
    abstract val abiTools: ConfigurableFileCollection

    @get:Inject
    abstract val workers: WorkerExecutor

    @TaskAction
    fun check() {
        val referenceFile = reference.singleFile
        if (!referenceFile.isFile) {
            throw GradleException("$referenceFile is missing. Run ./gradlew ${updateTask.get()} and commit it.")
        }
        workers.classLoaderIsolation { classpath.from(abiTools) }.submit(CompareAbiDumps::class.java) {
            expected.set(referenceFile)
            actual.set(this@CheckPublicApiTask.actual)
            updateTask.set(this@CheckPublicApiTask.updateTask)
        }
    }
}
