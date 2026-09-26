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
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ApiClassFilesTest {

    @Test
    fun `classes are API candidates, nested ones included`() {
        assertTrue(ApiClassFiles.isApiClass("com/example/sdk/Scanner.class"))
        assertTrue(ApiClassFiles.isApiClass("com/example/sdk/Scanner\$Result.class"))
    }

    @Test
    fun `generated and non-class files are not API`() {
        listOf(
            "com/example/sdk/R.class",
            "com/example/sdk/R\$string.class",
            "com/example/sdk/BuildConfig.class",
            "module-info.class",
            "META-INF/versions/9/com/example/Scanner.class",
            "META-INF/sdk.kotlin_module",
            "com/example/sdk/notes.txt",
        ).forEach { path -> assertFalse(path, ApiClassFiles.isApiClass(path)) }
    }

    @Test
    fun `collect walks directories and extracts only the API classes of jars`() {
        val root = Files.createTempDirectory("api-class-files").toFile()
        val classes = File(root, "classes/com/example").apply { mkdirs() }
        File(classes, "Scanner.class").writeText("scanner")
        File(classes, "BuildConfig.class").writeText("generated")
        val jar = File(root, "classes.jar")
        ZipOutputStream(jar.outputStream()).use { zip ->
            listOf("com/example/Result.class", "com/example/R.class", "META-INF/app.kotlin_module").forEach { name ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(name.toByteArray())
                zip.closeEntry()
            }
        }

        val collected = ApiClassFiles.collect(listOf(File(root, "classes")), listOf(jar), File(root, "extracted"))

        assertEquals(listOf("Result.class", "Scanner.class"), collected.map { it.name }.sorted())
        assertEquals("com/example/Result.class", collected.single { it.name == "Result.class" }.readText())
    }
}
