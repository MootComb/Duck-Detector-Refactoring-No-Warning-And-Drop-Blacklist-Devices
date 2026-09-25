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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import org.lsposed.hiddenapibypass.HiddenApiBypass

internal fun ensureHiddenApiAccess() {
    runCatching { HiddenApiBypass.addHiddenApiExemptions("") }
}

internal fun setField(target: Any, name: String, value: Any?) {
    val field = target.javaClass.getDeclaredField(name)
    field.isAccessible = true
    field.set(target, value)
}

internal fun getFieldValue(target: Any, name: String): Any? {
    return runCatching {
        val field = target.javaClass.getField(name)
        field.isAccessible = true
        field.get(target)
    }.recoverCatching {
        val field = target.javaClass.getDeclaredField(name)
        field.isAccessible = true
        field.get(target)
    }.getOrNull()
}

internal fun buildListEntriesArgs(
    parameterTypes: Array<Class<*>>,
    startPastAlias: String? = null,
): Array<Any?> {
    return parameterTypes.map { type ->
        when {
            type == Int::class.javaPrimitiveType || type == Int::class.java -> 0
            type == Long::class.javaPrimitiveType || type == Long::class.java -> -1L
            type == String::class.java -> startPastAlias
            type == Boolean::class.javaPrimitiveType || type == Boolean::class.java -> false
            else -> null
        }
    }.toTypedArray()
}

private fun findThrowable(
    throwable: Throwable,
    predicate: (Throwable) -> Boolean,
): Throwable? {
    var current: Throwable? = throwable
    while (current != null) {
        if (predicate(current)) {
            return current
        }
        current = current.cause
    }
    return null
}

private fun findRootCause(throwable: Throwable): Throwable {
    var current = throwable
    while (current.cause != null && current.cause !== current) {
        current = current.cause!!
    }
    return current
}

internal fun loadClass(className: String): Class<*> {
    return try {
        Class.forName(className)
    } catch (primary: ClassNotFoundException) {
        try {
            ClassLoader.getSystemClassLoader().loadClass(className)
        } catch (secondary: ClassNotFoundException) {
            try {
                HiddenApiBypass.invoke(Class::class.java, null, "forName", className) as Class<*>
            } catch (throwable: Throwable) {
                throw ClassNotFoundException("Unable to load hidden class $className", throwable)
            }
        }
    }
}

internal fun isKeystoreServiceSpecificException(throwable: Throwable): Boolean {
    return findThrowable(throwable) { it.javaClass.name == "android.os.ServiceSpecificException" } != null
}

internal fun keystoreServiceSpecificErrorCode(throwable: Throwable): Int? {
    val serviceSpecific = findThrowable(throwable) {
        it.javaClass.name == "android.os.ServiceSpecificException"
    } ?: return null
    return getFieldValue(serviceSpecific, "errorCode") as? Int
}

internal fun describeKeystoreThrowable(throwable: Throwable): String {
    val root = findRootCause(throwable)
    val serviceSpecificCode = keystoreServiceSpecificErrorCode(throwable)
    val detail = root.message?.takeIf { it.isNotBlank() }
    return when {
        serviceSpecificCode != null && detail != null -> "${root.javaClass.simpleName}(code $serviceSpecificCode): $detail"
        serviceSpecificCode != null -> "${root.javaClass.simpleName}(code $serviceSpecificCode)"
        detail != null -> "${root.javaClass.simpleName}: $detail"
        else -> root.javaClass.simpleName
    }
}
