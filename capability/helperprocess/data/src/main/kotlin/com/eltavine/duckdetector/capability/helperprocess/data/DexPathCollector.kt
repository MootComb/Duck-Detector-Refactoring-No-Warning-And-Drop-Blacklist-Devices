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

package com.eltavine.duckdetector.capability.helperprocess.data

import android.content.Context
import dalvik.system.BaseDexClassLoader
import java.io.File
import java.lang.reflect.Field

public data class DexPathObservation(
    val classPathEntries: List<String> = emptyList(),
    val sourceDir: String = "",
    val splitSourceDirs: List<String> = emptyList(),
)

public open class DexPathCollector(
    private val context: Context? = null,
    private val classLoaderProvider: () -> ClassLoader? = {
        context?.applicationContext?.classLoader ?: Thread.currentThread().contextClassLoader
    },
) {

    public open fun collect(): DexPathObservation? {
        val appContext = context?.applicationContext ?: return null
        val sourceDir = runCatching { appContext.applicationInfo.sourceDir }.getOrDefault("")
        val splitSourceDirs = runCatching {
            appContext.applicationInfo.splitSourceDirs?.toList().orEmpty()
        }.getOrDefault(emptyList())

        val entries = collectClassPathEntries(classLoaderProvider())
        return observe(
            entries = entries,
            sourceDir = sourceDir,
            splitSourceDirs = splitSourceDirs,
            packageName = appContext.packageName,
        )
    }

    public fun observe(
        entries: List<String>,
        sourceDir: String,
        splitSourceDirs: List<String>,
        packageName: String,
    ): DexPathObservation {
        val normalizedEntries = entries
            .map(::normalizePath)
            .filter { it.isNotBlank() }
            .filterNot(::isSystemPath)
            .filterNot { isOwnOverlayPath(it, packageName) }
            .distinct()
        return DexPathObservation(
            classPathEntries = normalizedEntries,
            sourceDir = normalizePath(sourceDir),
            splitSourceDirs = splitSourceDirs.map(::normalizePath).filter { it.isNotBlank() },
        )
    }

    protected open fun collectClassPathEntries(classLoader: ClassLoader?): List<String> {
        val loader = classLoader ?: return emptyList()
        val reflectedEntries = collectFromDexElements(loader)
        if (reflectedEntries.isNotEmpty()) {
            return reflectedEntries
        }
        return parseClassLoaderDescription(loader.toString())
    }

    private fun collectFromDexElements(classLoader: ClassLoader): List<String> {
        if (classLoader !is BaseDexClassLoader) {
            return emptyList()
        }
        return runCatching {
            val pathListField = findField(classLoader.javaClass, "pathList")
            val pathList = pathListField.get(classLoader) ?: return emptyList()
            val dexElementsField = findField(pathList.javaClass, "dexElements")
            val dexElements = dexElementsField.get(pathList) as? Array<*> ?: return emptyList()
            dexElements.mapNotNull { element ->
                when {
                    element == null -> null
                    else -> collectDexElementPath(element)
                }
            }
        }.getOrDefault(emptyList())
    }

    private fun collectDexElementPath(element: Any): String? {
        val dexFilePath = runCatching {
            val dexFileField = findField(element.javaClass, "dexFile")
            val dexFile = dexFileField.get(element)
            val method = dexFile?.javaClass?.methods?.firstOrNull { it.name == "getName" }
            method?.invoke(dexFile) as? String
        }.getOrNull()
        if (!dexFilePath.isNullOrBlank()) {
            return dexFilePath
        }

        val pathFields = listOf("path", "file", "zip")
        pathFields.forEach { fieldName ->
            val candidate = runCatching {
                val field = findField(element.javaClass, fieldName)
                field.get(element)
            }.getOrNull()
            when (candidate) {
                is File -> return candidate.absolutePath
                is String -> if (candidate.isNotBlank()) return candidate
            }
        }
        return null
    }

    private fun parseClassLoaderDescription(description: String): List<String> {
        val bracketContent = description.substringAfter('[', "")
            .substringBeforeLast(']', "")
            .ifBlank { description }
        return bracketContent
            .split(':', ',', ';')
            .map { it.trim() }
            .filter { it.contains('/') && !it.endsWith(".oat") && !it.endsWith(".vdex") }
    }

    private fun findField(type: Class<*>, name: String): Field {
        var current: Class<*>? = type
        while (current != null) {
            runCatching {
                return current.getDeclaredField(name).apply { isAccessible = true }
            }
            current = current.superclass
        }
        error("Field $name not found on ${type.name}")
    }

    private fun isSystemPath(path: String): Boolean {
        return path.startsWith("/system/") ||
                path.startsWith("/apex/") ||
                path.startsWith("/product/") ||
                path.startsWith("/vendor/") ||
                path.startsWith("/system_ext/") ||
                path.endsWith(".oat") ||
                path.endsWith(".vdex") ||
                path.endsWith(".art")
    }

    private fun isOwnOverlayPath(path: String, packageName: String): Boolean {
        if (packageName.isBlank()) {
            return false
        }
        val overlayMarker = "/$packageName/code_cache/.overlay/"
        return path.contains(overlayMarker) &&
                (path.endsWith(".dex") || path.endsWith(".jar") || path.endsWith(".zip") || path.endsWith(
                    ".apk"
                ))
    }

    private fun normalizePath(path: String): String {
        return path.trim()
            .replace('\\', '/')
            .substringBefore("!/")
            .ifBlank { "" }
    }
}
