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

import java.io.PrintWriter
import java.io.StringWriter
import java.util.spi.ToolProvider
import java.util.zip.ZipFile
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.Directory
import org.gradle.api.file.RegularFile
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

/** Writes javap's listing of every public and protected class member of the module's classes. */
@CacheableTask
abstract class DumpPublicApiTask : DefaultTask() {

    /** Class directories of an Android variant, from AGP's scoped `CLASSES` artifact. */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val classDirectories: ListProperty<Directory>

    /** Class jars of an Android variant, from the same artifact. */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val classJars: ListProperty<RegularFile>

    /** The class output of a JVM module. */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val jvmClasses: ConfigurableFileCollection

    @get:OutputFile
    abstract val dump: RegularFileProperty

    @TaskAction
    fun write() {
        val javap = ToolProvider.findFirst("javap")
            .orElseThrow { GradleException("javap is unavailable; run Gradle on a JDK") }
        val listings = sortedMapOf<String, String>()
        val directories = classDirectories.get().map { it.asFile } + jvmClasses.files.filter { it.isDirectory }
        directories.forEach { root ->
            root.walkTopDown().filter { it.isFile }.forEach { file ->
                PublicApiListing.className(file.relativeTo(root).invariantSeparatorsPath)?.let { name ->
                    listings[name] = javap.list(file.path)
                }
            }
        }
        classJars.get().forEach { jar ->
            ZipFile(jar.asFile).use { zip ->
                zip.entries().asSequence().mapNotNull { PublicApiListing.className(it.name) }.forEach { name ->
                    listings[name] = javap.list("-cp", jar.asFile.path, name)
                }
            }
        }
        dump.get().asFile.writeText(PublicApiListing.dump(listings))
    }

    private fun ToolProvider.list(vararg arguments: String): String {
        val output = StringWriter()
        val errors = StringWriter()
        if (run(PrintWriter(output), PrintWriter(errors), "-protected", *arguments) != 0) {
            throw GradleException("javap could not list ${arguments.last()}: $errors")
        }
        return output.toString()
    }
}

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

    @TaskAction
    fun check() {
        val referenceFile = reference.singleFile
        val update = updateTask.get()
        if (!referenceFile.isFile) {
            throw GradleException("$referenceFile is missing. Run ./gradlew $update and commit it.")
        }
        val expected = referenceFile.readText()
        val current = actual.get().asFile.readText()
        if (expected != current) {
            val difference = PublicApiListing.difference(expected, current).joinToString(separator = "\n") { "  $it" }
            throw GradleException(
                "The public API no longer matches $referenceFile:\n$difference\n" +
                    "If the change is intended, run ./gradlew $update and commit the updated dump.",
            )
        }
    }
}
