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

import com.eltavine.duckdetector.core.platform.HiddenPlatformFailure
import com.eltavine.duckdetector.core.platform.PlatformFailureName
import java.lang.reflect.InvocationTargetException
import org.lsposed.hiddenapibypass.HiddenApiBypass

internal object Keystore2GrantReflection {
    fun readFieldValue(target: Any?, name: String): Any? {
        if (target == null) {
            return null
        }
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

    fun readByteArrayField(target: Any?, name: String): ByteArray? {
        return readFieldValue(target, name) as? ByteArray
    }

    fun readLongField(target: Any?, name: String): Long? {
        return when (val raw = readFieldValue(target, name)) {
            is Long -> raw
            is Int -> raw.toLong()
            else -> null
        }
    }

    fun setField(target: Any, name: String, value: Any?) {
        val field = target.javaClass.getDeclaredField(name)
        field.isAccessible = true
        field.set(target, value)
    }

    fun ensureHiddenApiAccess() {
        runCatching { HiddenApiBypass.addHiddenApiExemptions("") }
    }

    fun loadClass(className: String): Class<*> {
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

    fun describeThrowable(throwable: Throwable): String {
        val root = findRootCause(throwable)
        val code = extractServiceSpecificErrorCode(throwable)
        val type = PlatformFailureName.of(root)
        val message = root.message?.takeIf { it.isNotBlank() }
        return when {
            code != null && message != null -> "$type(code $code): $message"
            code != null -> "$type(code $code)"
            message != null -> "$type: $message"
            else -> type
        }
    }

    fun extractServiceSpecificErrorCode(throwable: Throwable): Int? {
        return findThrowable(throwable, HiddenPlatformFailure::isServiceSpecific)
            ?.let(HiddenPlatformFailure::serviceSpecificErrorCode)
    }

    fun findThrowable(
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

    fun findRootCause(throwable: Throwable): Throwable {
        var current = throwable
        while (current is InvocationTargetException && current.cause != null) {
            current = current.cause!!
        }
        while (current.cause != null && current.cause !== current) {
            current = current.cause!!
        }
        return current
    }
}
