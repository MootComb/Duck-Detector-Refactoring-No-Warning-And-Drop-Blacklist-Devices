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

import java.util.ServiceLoader
import org.gradle.api.GradleException
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.workers.WorkAction
import org.gradle.workers.WorkParameters
import org.jetbrains.kotlin.abi.tools.AbiFilters
import org.jetbrains.kotlin.abi.tools.AbiTools
import org.jetbrains.kotlin.abi.tools.AbiToolsFactory

/**
 * Kotlin's ABI tools, found as the Kotlin Gradle plugin finds them: through their service entry, in
 * the isolated worker class loader that holds `org.jetbrains.kotlin:abi-tools`.
 */
private fun WorkAction<*>.abiTools(): AbiTools =
    ServiceLoader.load(AbiToolsFactory::class.java, javaClass.classLoader).single().get()

/** Writes the ABI dump of a module's class files. */
abstract class WriteAbiDump : WorkAction<WriteAbiDump.Parameters> {

    interface Parameters : WorkParameters {
        val classFiles: ConfigurableFileCollection
        val dump: RegularFileProperty
    }

    override fun execute() {
        parameters.dump.get().asFile.bufferedWriter().use { writer ->
            abiTools().printJvmDump(writer, parameters.classFiles.files, AbiFilters.EMPTY)
        }
    }
}

/** Fails with the ABI tools' diff when a module's dump differs from the committed one. */
abstract class CompareAbiDumps : WorkAction<CompareAbiDumps.Parameters> {

    interface Parameters : WorkParameters {
        val expected: RegularFileProperty
        val actual: RegularFileProperty
        val updateTask: Property<String>
    }

    override fun execute() {
        val expected = parameters.expected.get().asFile
        val actual = parameters.actual.get().asFile
        if (expected.readText() != actual.readText()) {
            throw GradleException(
                "The public API no longer matches $expected:\n${abiTools().filesDiff(expected, actual)}\n" +
                    "If the change is intended, run ./gradlew ${parameters.updateTask.get()} and commit the updated dump.",
            )
        }
    }
}
