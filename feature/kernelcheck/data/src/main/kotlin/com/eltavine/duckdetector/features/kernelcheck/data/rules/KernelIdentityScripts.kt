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

package com.eltavine.duckdetector.features.kernelcheck.data.rules

import java.util.LinkedHashSet

/** Finds emoji, CJK and other non-Latin script characters in kernel identity strings. */
internal object KernelIdentityScripts {
    private const val MAX_SCRIPT_SAMPLE_COUNT = 8

    fun findEmojis(
        text: String,
    ): List<String> {
        val matches = LinkedHashSet<String>()
        var index = 0
        while (index < text.length) {
            val codePoint = text.codePointAt(index)
            if (isEmoji(codePoint)) {
                matches += String(Character.toChars(codePoint))
            }
            index += Character.charCount(codePoint)
        }
        return matches.toList()
    }

    private fun isEmoji(
        codePoint: Int,
    ): Boolean {
        return when (codePoint) {
            in 0x1F600..0x1F64F,
            in 0x1F300..0x1F5FF,
            in 0x1F680..0x1F6FF,
            in 0x1F900..0x1F9FF,
            in 0x1FA00..0x1FA6F,
            in 0x1FA70..0x1FAFF,
            in 0x2700..0x27BF,
            in 0x2600..0x26FF,
            in 0x1F1E0..0x1F1FF -> true

            else -> false
        }
    }

    fun findChineseCharacters(
        text: String,
    ): List<String> {
        val matches = LinkedHashSet<String>()
        var index = 0
        while (index < text.length) {
            val codePoint = text.codePointAt(index)
            if (isChineseCharacter(codePoint)) {
                matches += String(Character.toChars(codePoint))
            }
            index += Character.charCount(codePoint)
        }
        return matches.toList()
    }

    private fun isChineseCharacter(
        codePoint: Int,
    ): Boolean {
        return when (codePoint) {
            in 0x4E00..0x9FFF,
            in 0x3400..0x4DBF,
            in 0x20000..0x2A6DF,
            in 0x2A700..0x2B73F,
            in 0x2B740..0x2B81F,
            in 0x2B820..0x2CEAF,
            in 0xF900..0xFAFF,
            in 0x2F800..0x2FA1F -> true

            else -> false
        }
    }

    fun findNonLatinScriptCharacters(
        text: String,
    ): NonLatinScriptScanResult {
        val scripts = LinkedHashSet<String>()
        val samples = LinkedHashSet<String>()
        var index = 0
        while (index < text.length) {
            val codePoint = text.codePointAt(index)
            if (isUnexpectedNonLatinScript(codePoint)) {
                scripts += unicodeScriptLabel(Character.UnicodeScript.of(codePoint))
                if (samples.size < MAX_SCRIPT_SAMPLE_COUNT) {
                    samples += String(Character.toChars(codePoint))
                }
            }
            index += Character.charCount(codePoint)
        }
        return NonLatinScriptScanResult(
            scriptNames = scripts.toList(),
            samples = samples.toList(),
        )
    }

    private fun isUnexpectedNonLatinScript(
        codePoint: Int,
    ): Boolean {
        if (!Character.isLetter(codePoint)) {
            return false
        }
        return when (Character.UnicodeScript.of(codePoint)) {
            Character.UnicodeScript.LATIN,
            Character.UnicodeScript.COMMON,
            Character.UnicodeScript.INHERITED,
            Character.UnicodeScript.HAN -> false

            else -> true
        }
    }

    private fun unicodeScriptLabel(
        script: Character.UnicodeScript,
    ): String {
        return when (script) {
            Character.UnicodeScript.ARABIC -> "Arabic"
            Character.UnicodeScript.ARMENIAN -> "Armenian"
            Character.UnicodeScript.BENGALI -> "Bengali"
            Character.UnicodeScript.CYRILLIC -> "Cyrillic"
            Character.UnicodeScript.DEVANAGARI -> "Devanagari"
            Character.UnicodeScript.ETHIOPIC -> "Ethiopic"
            Character.UnicodeScript.GEORGIAN -> "Georgian"
            Character.UnicodeScript.GREEK -> "Greek"
            Character.UnicodeScript.GUJARATI -> "Gujarati"
            Character.UnicodeScript.GURMUKHI -> "Gurmukhi"
            Character.UnicodeScript.HANGUL -> "Hangul"
            Character.UnicodeScript.HEBREW -> "Hebrew"
            Character.UnicodeScript.HIRAGANA -> "Hiragana"
            Character.UnicodeScript.KANNADA -> "Kannada"
            Character.UnicodeScript.KATAKANA -> "Katakana"
            Character.UnicodeScript.KHMER -> "Khmer"
            Character.UnicodeScript.LAO -> "Lao"
            Character.UnicodeScript.MALAYALAM -> "Malayalam"
            Character.UnicodeScript.MYANMAR -> "Myanmar"
            Character.UnicodeScript.ORIYA -> "Oriya"
            Character.UnicodeScript.SINHALA -> "Sinhala"
            Character.UnicodeScript.TAMIL -> "Tamil"
            Character.UnicodeScript.TELUGU -> "Telugu"
            Character.UnicodeScript.THAI -> "Thai"
            else -> script.name.lowercase()
                .split('_')
                .joinToString(" ") { part ->
                    part.replaceFirstChar { char -> char.uppercase() }
                }
        }
    }
}

internal data class NonLatinScriptScanResult(
    val scriptNames: List<String>,
    val samples: List<String>,
)
