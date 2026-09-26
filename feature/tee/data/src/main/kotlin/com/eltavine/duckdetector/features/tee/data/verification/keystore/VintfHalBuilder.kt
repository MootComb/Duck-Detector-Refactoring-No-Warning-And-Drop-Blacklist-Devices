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

internal data class HalBuilder(
    val sourcePath: String,
    val format: String,
    var halName: String = "",
    val versions: MutableList<String> = mutableListOf(),
    val interfaces: MutableMap<String, MutableSet<String>> = mutableMapOf(),
    val fqnames: MutableList<String> = mutableListOf(),
) {
    fun toDeclarations(): List<VintfKeyMintVersionDeclaration> {
        return when (halName) {
            KEYMINT_HAL_NAME -> keyMintDeclarations()
            KEYMASTER_HAL_NAME -> keymasterDeclarations()
            else -> emptyList()
        }
    }

    private fun keyMintDeclarations(): List<VintfKeyMintVersionDeclaration> {
        val instances = interfaceInstances(KEYMINT_INTERFACE_NAME)
            .filter { it == DEFAULT_INSTANCE || it == STRONGBOX_INSTANCE }
        if (instances.isEmpty()) {
            return emptyList()
        }
        // Versionless AIDL HAL declarations mean version 1 in VINTF practice; treating them as missing
        // would create a false NO_DECLARATION / false legacy skip on valid KeyMint 1 devices.
        // VINTF 里未显式写 version 的 AIDL HAL 在实践中等价于 version 1；如果当作缺失处理，会把
        // 合法的 KeyMint 1 设备误报成没有声明，甚至误走 legacy skip。
        val aidlVersions = versions.ifEmpty { listOf(DEFAULT_AIDL_VERSION) }
        return instances.flatMap { instance ->
            aidlVersions.mapNotNull { version ->
                version.toIntOrNull()?.takeIf { it > 0 }?.let { aidlVersion ->
                    VintfKeyMintVersionDeclaration(
                        family = VintfKeyMintVersionFamily.KEYMINT_AIDL,
                        sourcePath = sourcePath,
                        format = format,
                        halName = halName,
                        interfaceName = KEYMINT_INTERFACE_NAME,
                        instance = instance,
                        vintfVersion = version,
                        expectedKeymasterVersion = aidlVersion * 100,
                        expectedAttestationVersion = aidlVersion * 100,
                    )
                }
            }
        }
    }

    private fun interfaceInstances(interfaceName: String): Set<String> {
        val fqnameInstances = fqnames.mapNotNull { fqname ->
            val name = fqname.substringAfter("::", fqname).substringBefore("/")
            val instance = fqname.substringAfter("/", "")
            instance.takeIf { name == interfaceName && it.isNotEmpty() }
        }
        return (interfaces[interfaceName].orEmpty() + fqnameInstances).toSet()
    }

    private fun keymasterDeclarations(): List<VintfKeyMintVersionDeclaration> {
        // For HIDL we must preserve the exact version-instance association from fqname.
        // A naive cross-product would wrongly synthesize nonexistent pairs such as
        // default@4.1 when the manifest only declares strongbox@4.1.
        // HIDL 这里必须保留 fqname 中“版本-实例”的原始绑定关系；如果做笛卡尔积，就会伪造出
        // manifest 根本没声明的 default@4.1 之类组合。
        val interfaceDeclaredInstances = interfaces[KEYMASTER_INTERFACE_NAME].orEmpty()
            .filter { it == DEFAULT_INSTANCE || it == STRONGBOX_INSTANCE }
        val interfaceDeclarations = interfaceDeclaredInstances.flatMap { instance ->
            versions.flatMap(::expandHidlVersions).distinct().mapNotNull { version ->
                val expected = expectedLegacyVersions(version) ?: return@mapNotNull null
                legacyDeclaration(instance, version, expected)
            }
        }
        val fqnameDeclarations = fqnames.mapNotNull { fqname ->
            val parsed = parseHidlFqname(fqname) ?: return@mapNotNull null
            if (
                parsed.interfaceName != KEYMASTER_INTERFACE_NAME ||
                (parsed.instance != DEFAULT_INSTANCE && parsed.instance != STRONGBOX_INSTANCE)
            ) {
                return@mapNotNull null
            }
            val expected = expectedLegacyVersions(parsed.version) ?: return@mapNotNull null
            legacyDeclaration(parsed.instance, parsed.version, expected)
        }
        return (interfaceDeclarations + fqnameDeclarations).distinct()
    }

    private fun legacyDeclaration(
        instance: String,
        version: String,
        expected: Pair<Int, Int>,
    ): VintfKeyMintVersionDeclaration {
        return VintfKeyMintVersionDeclaration(
            family = VintfKeyMintVersionFamily.KEYMASTER_HIDL,
            sourcePath = sourcePath,
            format = format,
            halName = halName,
            interfaceName = KEYMASTER_INTERFACE_NAME,
            instance = instance,
            vintfVersion = version,
            expectedKeymasterVersion = expected.first,
            expectedAttestationVersion = expected.second,
        )
    }

    private fun parseHidlFqname(fqname: String): ParsedHidlFqname? {
        val match = HIDL_FQNAME_REGEX.matchEntire(fqname) ?: return null
        return ParsedHidlFqname(
            version = match.groupValues[1],
            interfaceName = match.groupValues[2],
            instance = match.groupValues[3],
        )
    }
}

private data class ParsedHidlFqname(
    val version: String,
    val interfaceName: String,
    val instance: String,
)

internal const val KEYMINT_HAL_NAME = "android.hardware.security.keymint"

internal const val KEYMASTER_HAL_NAME = "android.hardware.keymaster"

internal const val KEYMINT_INTERFACE_NAME = "IKeyMintDevice"

internal const val KEYMASTER_INTERFACE_NAME = "IKeymasterDevice"

internal const val DEFAULT_INSTANCE = "default"

internal const val STRONGBOX_INSTANCE = "strongbox"

private const val DEFAULT_AIDL_VERSION = "1"

private val HIDL_FQNAME_REGEX = Regex("^@([0-9]+(?:\\.[0-9]+)?)::([^/]+)/(.+)$")

private fun expectedLegacyVersions(version: String): Pair<Int, Int>? {
    return when (version) {
        "3.0" -> 3 to 2
        "4.0" -> 4 to 3
        "4.1" -> 41 to 4
        else -> null
    }
}

private fun expandHidlVersions(version: String): List<String> {
    val range = HIDL_VERSION_RANGE_REGEX.matchEntire(version) ?: return listOf(version)
    val major = range.groupValues[1]
    val firstMinor = range.groupValues[2].toInt()
    val lastMinor = range.groupValues[3].toInt()
    return (firstMinor..lastMinor).map { minor -> "$major.$minor" }
}

private val HIDL_VERSION_RANGE_REGEX = Regex("^([0-9]+)\\.([0-9]+)-([0-9]+)$")
