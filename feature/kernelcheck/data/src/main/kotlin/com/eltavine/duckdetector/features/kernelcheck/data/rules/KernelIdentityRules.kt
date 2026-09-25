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

/** Identity and boot command line rules that recognise community kernels and unlocked boot state. */
internal object KernelIdentityRules {
    val TELEGRAM_REGEX =
        Regex("""\bTG\b|\btg\b|\bTelegram\b|\btelegram\b|t\.me/""", RegexOption.IGNORE_CASE)

    val MENTION_REGEX = Regex("@[A-Za-z0-9_]+")

    private val CUSTOM_KERNEL_KEYWORDS = listOf(
        "xiaoxiaow",
        "qdykernel",
        "numbers",
        "cctv",
        "shirkneko",
        "mirinfork",
        "brokestar",
        "sukisu",
        "Glow-v",
        "aptkernel",
        "coolzyd9107",
        "aptusitu",
        "Winkmoon",
        "ShirokoNeko",
    )

    private val CASE_SENSITIVE_KEYWORDS = listOf("OKI")

    val KEYWORD_SCAN_COUNT =
        CUSTOM_KERNEL_KEYWORDS.size + CASE_SENSITIVE_KEYWORDS.size + 6

    // Only the kernel release major number is checked - minor line, patch level, and
    // kernel.org's own longterm/LTS tagging are intentionally ignored. Linux major numbers
    // change roughly once per decade, so this stays valid far longer than a minor-line list.
    private val KNOWN_KERNEL_MAJOR_VERSIONS = setOf("4", "5", "6")

    private val KERNEL_RELEASE_MAJOR_REGEX = Regex("""^(\d{1,2})\.\d{1,3}\.\d+""")

    val CMDLINE_CHECKS = listOf(
        CmdlineCheck(
            "androidboot.verifiedbootstate=orange",
            "Bootloader unlocked (orange)",
            true
        ),
        CmdlineCheck("androidboot.verifiedbootstate=yellow", "Self-signed boot (yellow)", true),
        CmdlineCheck("androidboot.enable_dm_verity=0", "dm-verity disabled", true),
        CmdlineCheck("androidboot.secboot=disabled", "Secure boot disabled", true),
        CmdlineCheck("androidboot.vbmeta.device_state=unlocked", "vbmeta unlocked", true),
        CmdlineCheck("skip_initramfs", "Skip initramfs (possible root)", false),
        CmdlineCheck("init=/sbin", "Custom init path", true),
        CmdlineCheck("init=/system", "Custom init path", false),
        CmdlineCheck("androidboot.force_normal_boot=1", "Force normal boot", false),
        CmdlineCheck("magisk", "Magisk reference in cmdline", true),
        CmdlineCheck("ksu", "KernelSU reference in cmdline", true),
        CmdlineCheck("apatch", "APatch reference in cmdline", true),
        CmdlineCheck("rootfs=", "Custom rootfs", false),
        CmdlineCheck("androidboot.slot_suffix=", "Slot suffix present", false),
    )

    fun detectCustomKernelKeywords(
        input: String,
    ): List<String> {
        if (input.isBlank()) {
            return emptyList()
        }
        return buildList {
            CUSTOM_KERNEL_KEYWORDS.forEach { keyword ->
                if (input.contains(keyword, ignoreCase = true)) {
                    add(keyword)
                }
            }
            CASE_SENSITIVE_KEYWORDS.forEach { keyword ->
                if (input.contains(keyword)) {
                    add(keyword)
                }
            }
        }
    }

    fun detectNonReleaseKernelMajorVersion(
        unameOutput: String,
    ): String? {
        val major = extractKernelReleaseMajor(unameOutput) ?: return null
        return major.takeIf { it !in KNOWN_KERNEL_MAJOR_VERSIONS }
    }

    private fun extractKernelReleaseMajor(
        source: String,
    ): String? {
        // Genuine `uname -a` output on Android is "Linux localhost <release> ...", because init sets
        // the UTS nodename with `hostname localhost` (system/core rootdir/init.rc). Requiring
        // that exact prefix anchors extraction to a real uname invocation and rejects the
        // /proc/version fallback ("Linux version <release> ...") and any other reformatted or
        // spoofed identity string, instead of guessing the release field from its position alone.
        val tokens = source.trim().split(Regex("""\s+"""))
        if (tokens.getOrNull(0) != "Linux" || tokens.getOrNull(1) != "localhost") {
            return null
        }
        val releaseToken = tokens.getOrNull(2) ?: return null
        return KERNEL_RELEASE_MAJOR_REGEX.find(releaseToken)?.groupValues?.get(1)
    }

    fun detectCriticalCmdlineFallback(
        procCmdline: String,
    ): List<String> {
        if (procCmdline.isBlank()) {
            return emptyList()
        }
        return CMDLINE_CHECKS.filter {
            it.isCritical && procCmdline.contains(
                it.pattern,
                ignoreCase = true
            )
        }
            .map { it.description }
    }
}

internal data class CmdlineCheck(
    val pattern: String,
    val description: String,
    val isCritical: Boolean,
)
