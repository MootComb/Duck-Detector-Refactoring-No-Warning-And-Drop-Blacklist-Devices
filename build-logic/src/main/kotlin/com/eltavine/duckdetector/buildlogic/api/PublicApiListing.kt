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

/** Turns javap listings into the text of a public API dump, and compares two dumps. */
internal object PublicApiListing {

    private val generatedSimpleNames = Regex("""R|R\$.*|BuildConfig|module-info""")

    /** The binary name of the class file at [relativePath] in a class directory or jar, or null when it is not API. */
    fun className(relativePath: String): String? {
        if (!relativePath.endsWith(".class") || relativePath.startsWith("META-INF/")) {
            return null
        }
        val name = relativePath.removeSuffix(".class").replace('/', '.')
        return name.takeUnless { generatedSimpleNames.matches(it.substringAfterLast('.')) }
    }

    /**
     * The listing of every public class in class name order, without javap's `Compiled from` lines.
     *
     * javap also lists the public members of classes that are not public themselves, such as the
     * classes Kotlin compiles lambdas and coroutines into; those are not API.
     */
    fun dump(listings: Map<String, String>): String =
        listings.toSortedMap().values
            .map { listing -> listing.lines().filterNot { it.startsWith("Compiled from ") }.joinToString("\n").trim() }
            .filter { it.startsWith("public ") }
            .joinToString(separator = "\n\n", postfix = "\n")

    /** The lines only [expected] has, marked `-`, then the lines only [actual] has, marked `+`. */
    fun difference(expected: String, actual: String): List<String> {
        val expectedLines = expected.lines().filter(String::isNotBlank)
        val actualLines = actual.lines().filter(String::isNotBlank)
        return (expectedLines - actualLines.toSet()).map { "- $it" } + (actualLines - expectedLines.toSet()).map { "+ $it" }
    }
}
