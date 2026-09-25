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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PublicApiListingTest {

    @Test
    fun `class files map to binary names`() {
        assertEquals("com.example.sdk.Scanner", PublicApiListing.className("com/example/sdk/Scanner.class"))
        assertEquals("com.example.sdk.Scanner\$Result", PublicApiListing.className("com/example/sdk/Scanner\$Result.class"))
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
        ).forEach { path -> assertNull(path, PublicApiListing.className(path)) }
    }

    @Test
    fun `the dump orders public classes by name and drops source lines and every other class`() {
        val dump = PublicApiListing.dump(
            mapOf(
                "com.example.B" to "Compiled from \"B.kt\"\npublic final class com.example.B {\n  public void run();\n}\n",
                "com.example.Hidden" to "Compiled from \"Hidden.kt\"\n",
                "com.example.B\$run\$1" to "Compiled from \"B.kt\"\nfinal class com.example.B\$run\$1 {\n  public void invoke();\n}\n",
                "com.example.A" to "Compiled from \"A.kt\"\npublic interface com.example.A {\n}\n",
            ),
        )

        assertEquals(
            "public interface com.example.A {\n}\n\npublic final class com.example.B {\n  public void run();\n}\n",
            dump,
        )
    }

    @Test
    fun `the difference lists removed lines before added lines`() {
        val expected = "public final class A {\n  public void old();\n}\n"
        val actual = "public final class A {\n  public void new();\n}\n"

        assertEquals(listOf("-   public void old();", "+   public void new();"), PublicApiListing.difference(expected, actual))
    }
}
