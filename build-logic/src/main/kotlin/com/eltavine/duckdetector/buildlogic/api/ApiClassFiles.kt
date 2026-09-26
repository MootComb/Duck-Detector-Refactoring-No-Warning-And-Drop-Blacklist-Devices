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

import java.io.File
import java.util.zip.ZipFile

/** Picks the class files whose declarations can be public API from class directories and jars. */
internal object ApiClassFiles {

    private val generatedSimpleNames = Regex("""R|R\$.*|BuildConfig|module-info""")

    /** Whether the entry at [relativePath] of a class directory or jar is a class that can be API. */
    fun isApiClass(relativePath: String): Boolean {
        if (!relativePath.endsWith(".class") || relativePath.startsWith("META-INF/")) {
            return false
        }
        return !generatedSimpleNames.matches(relativePath.removeSuffix(".class").substringAfterLast('/'))
    }

    /** The API class files under [directories], and those of [jars] extracted into [extractionDirectory]. */
    fun collect(directories: List<File>, jars: List<File>, extractionDirectory: File): List<File> {
        val fromDirectories = directories.flatMap { root ->
            root.walkTopDown().filter { it.isFile && isApiClass(it.relativeTo(root).invariantSeparatorsPath) }.toList()
        }
        extractionDirectory.deleteRecursively()
        val fromJars = jars.flatMapIndexed { index, jar -> extract(jar, File(extractionDirectory, index.toString())) }
        return (fromDirectories + fromJars).sortedBy { it.path }
    }

    private fun extract(jar: File, into: File): List<File> = ZipFile(jar).use { zip ->
        zip.entries().asSequence().filter { !it.isDirectory && isApiClass(it.name) }.map { entry ->
            val target = File(into, entry.name)
            check(target.canonicalPath.startsWith(into.canonicalPath + File.separator)) { "${entry.name} leaves $jar" }
            target.parentFile.mkdirs()
            zip.getInputStream(entry).use { input -> target.outputStream().use { input.copyTo(it) } }
            target
        }.toList()
    }
}
