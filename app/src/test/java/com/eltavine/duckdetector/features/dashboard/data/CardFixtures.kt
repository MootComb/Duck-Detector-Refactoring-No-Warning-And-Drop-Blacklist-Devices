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

package com.eltavine.duckdetector.features.dashboard.data

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import java.lang.reflect.Constructor
import java.lang.reflect.ParameterizedType
import java.lang.reflect.Type
import java.lang.reflect.WildcardType
import java.util.Random

/**
 * Builds fully populated card models for export tests.
 *
 * Every constructor parameter receives a value. Strings and list sizes are drawn from a seeded
 * generator over the shapes the report layout treats differently (blank, padded, multi-line,
 * over-long, containing " = " or " | "); with [minListSize] of at least one, every list is
 * populated, so a mapper that drops or reorders a block changes the rendered report.
 */
internal class CardFixtures(
    seed: Int,
    private val minListSize: Int = 0,
) {

    private val random = Random(seed.toLong())
    private var counter = 0

    fun <T : Any> create(type: Class<T>): T = requireNotNull(type.cast(build(type)))

    private fun build(type: Type): Any = when {
        type == String::class.java -> nextString()
        type == Boolean::class.javaPrimitiveType || type == java.lang.Boolean::class.java -> random.nextBoolean()
        type == Int::class.javaPrimitiveType || type == Integer::class.java -> next()
        type == Long::class.javaPrimitiveType || type == java.lang.Long::class.java -> next().toLong()
        type == Double::class.javaPrimitiveType || type == java.lang.Double::class.java -> next() / 4.0
        type == Float::class.javaPrimitiveType || type == java.lang.Float::class.java -> next() / 4f
        type == DetectorStatus::class.java -> nextStatus()
        type is ParameterizedType && (type.rawType == List::class.java || type.rawType == Collection::class.java) ->
            List(minListSize + random.nextInt(4 - minListSize.coerceAtMost(2))) { build(elementType(type)) }

        type is Class<*> && type.isEnum -> type.enumConstants[random.nextInt(type.enumConstants.size)]
        type is Class<*> -> construct(type)
        else -> error("CardFixtures cannot build $type")
    }

    private fun construct(type: Class<*>): Any {
        val constructor = primaryConstructor(type)
        val arguments = constructor.genericParameterTypes.map { build(it) }
        return constructor.newInstance(*arguments.toTypedArray())
    }

    private fun primaryConstructor(type: Class<*>): Constructor<*> =
        type.declaredConstructors
            .filterNot { constructor ->
                constructor.parameterTypes.any { it.name == "kotlin.jvm.internal.DefaultConstructorMarker" }
            }
            .maxByOrNull { it.parameterCount }
            ?.also { it.isAccessible = true }
            ?: error("${type.name} has no usable constructor")

    private fun elementType(type: ParameterizedType): Type {
        val argument = type.actualTypeArguments.single()
        return if (argument is WildcardType) argument.upperBounds.single() else argument
    }

    private fun nextStatus(): DetectorStatus = when (random.nextInt(5)) {
        0 -> DetectorStatus.danger()
        1 -> DetectorStatus.warning()
        2 -> DetectorStatus.allClear()
        3 -> DetectorStatus.info(InfoKind.ERROR)
        else -> DetectorStatus(DetectionSeverity.INFO, InfoKind.SUPPORT)
    }

    private fun nextString(): String {
        val n = next()
        return when (random.nextInt(9)) {
            0 -> "Value $n"
            1 -> "  Padded value $n  "
            2 -> "Line one $n\nLine two $n\n\n  Line three  "
            3 -> "key = value $n"
            4 -> "left | right $n"
            5 -> ""
            6 -> "   "
            7 -> "A long detail line that deliberately exceeds sixty characters in length $n"
            else -> "Unicode ✓ détail $n"
        }
    }

    private fun next(): Int = counter++
}
