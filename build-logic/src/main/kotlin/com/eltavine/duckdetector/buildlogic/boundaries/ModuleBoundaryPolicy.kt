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

package com.eltavine.duckdetector.buildlogic.boundaries

import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

enum class ModuleKind(val id: String) {
    ANDROID_APPLICATION("android-application"),
    ANDROID_LIBRARY("android-library"),

    /** Packages other library modules into one published AAR and holds no code of its own. */
    ANDROID_FUSED_LIBRARY("android-fused-library"),
    JVM("jvm"),
    ;

    companion object {
        fun fromId(id: String): ModuleKind? = entries.firstOrNull { it.id == id }
    }
}

/**
 * A module the policy names explicitly: the composition root and every module of a group without
 * layers. [allowedProjectDependencies] are module paths or `*` globs over them.
 */
data class ModuleMember(
    val kind: ModuleKind,
    val ui: Boolean,
    val allowedProjectDependencies: Set<String>,
)

/**
 * The template every `group:unit:layer` module of a layered group follows, so adding a unit needs
 * no policy change. [mayDependOn] names layers of the same unit; [mayUse] holds `*` globs over the
 * modules outside the unit.
 */
data class LayerRule(
    val kind: ModuleKind,
    val ui: Boolean,
    val mayDependOn: Set<String>,
    val mayUse: Set<String>,
)

/**
 * Parsed form of `.github/policies/module-boundaries.json`.
 *
 * Paths follow `:group:unit[:layer]`. [dependencyDirection] orders groups from the composition
 * root down to the most neutral code; dependencies may only point along that order. Only UI
 * modules may apply Compose or depend on [uiOnlyDependencies], and nothing that is not UI may
 * depend on a module that is.
 */
data class ModuleBoundaryPolicy(
    val members: Map<String, ModuleMember>,
    val compositionRoot: String,
    val dependencyDirection: List<String>,
    val isolatedGroups: Set<String>,
    val groupLayers: Map<String, Map<String, LayerRule>>,
    val jvmForbiddenDependencies: List<String>,
    val uiOnlyDependencies: List<String>,
) {
    /** The rule that governs [path], or null when the policy does not classify it. */
    fun classify(path: String): ModuleRule? {
        members[path]?.let { member -> return ModuleRule(path, member.kind, member.ui, layer = null) }
        val modulePath = ModulePath(path)
        val layers = groupLayers[modulePath.group] ?: return null
        if (modulePath.depth != LAYERED_DEPTH) {
            return null
        }
        val rule = layers[modulePath.layer] ?: return null
        return ModuleRule(path, rule.kind, rule.ui, layer = rule)
    }

    companion object {
        const val SCHEMA_VERSION = 2
        const val RELATIVE_PATH = ".github/policies/module-boundaries.json"
        const val LAYERED_DEPTH = 3

        private val TOP_LEVEL_KEYS = setOf("schema_version", "rules", "members")
        private val RULE_KEYS = setOf(
            "composition_root",
            "dependency_direction",
            "isolated_groups",
            "group_layers",
            "jvm_forbidden_dependencies",
            "ui_only_dependencies",
        )
        private val MEMBER_KEYS = setOf("kind", "ui", "allowed_project_dependencies")
        private val LAYER_KEYS = setOf("kind", "ui", "may_depend_on", "may_use")

        fun parse(text: String): ModuleBoundaryPolicy {
            val document = try {
                JSONObject(text)
            } catch (error: JSONException) {
                throw ModuleBoundaryPolicyException("policy is not valid JSON: ${error.message}")
            }
            document.requireExactKeys(TOP_LEVEL_KEYS, "policy")
            val schemaVersion = document.opt("schema_version")
            if (schemaVersion != SCHEMA_VERSION) {
                throw ModuleBoundaryPolicyException("unsupported schema_version $schemaVersion")
            }
            val rules = document.requireObject("rules", "policy")
            rules.requireExactKeys(RULE_KEYS, "rules")
            val membersObject = document.requireObject("members", "policy")
            val members = membersObject.keySet().sorted().associateWith { path ->
                val member = membersObject.requireObject(path, "members")
                member.requireExactKeys(MEMBER_KEYS, "member $path")
                ModuleMember(
                    kind = member.requireKind("kind", "member $path"),
                    ui = member.requireBoolean("ui", "member $path"),
                    allowedProjectDependencies = member.requireUniqueStrings(
                        "allowed_project_dependencies",
                        "member $path",
                    ).toSet(),
                )
            }
            if (members.isEmpty()) {
                throw ModuleBoundaryPolicyException("policy declares no members")
            }
            val layersObject = rules.requireObject("group_layers", "rules")
            val groupLayers = layersObject.keySet().sorted().associateWith { group ->
                val layers = layersObject.requireObject(group, "group_layers")
                layers.keySet().sorted().associateWith { layer ->
                    val rule = layers.requireObject(layer, "group_layers.$group")
                    rule.requireExactKeys(LAYER_KEYS, "layer $group:$layer")
                    LayerRule(
                        kind = rule.requireKind("kind", "layer $group:$layer"),
                        ui = rule.requireBoolean("ui", "layer $group:$layer"),
                        mayDependOn = rule.requireUniqueStrings("may_depend_on", "layer $group:$layer").toSet(),
                        mayUse = rule.requireUniqueStrings("may_use", "layer $group:$layer").toSet(),
                    )
                }
            }
            return ModuleBoundaryPolicy(
                members = members,
                compositionRoot = rules.requireString("composition_root", "rules"),
                dependencyDirection = rules.requireUniqueStrings("dependency_direction", "rules"),
                isolatedGroups = rules.requireUniqueStrings("isolated_groups", "rules").toSet(),
                groupLayers = groupLayers,
                jvmForbiddenDependencies = rules.requireUniqueStrings("jvm_forbidden_dependencies", "rules"),
                uiOnlyDependencies = rules.requireUniqueStrings("ui_only_dependencies", "rules"),
            )
        }

        private fun JSONObject.requireExactKeys(expected: Set<String>, owner: String) {
            val actual = keySet()
            if (actual != expected) {
                val missing = (expected - actual).sorted()
                val unexpected = (actual - expected).sorted()
                throw ModuleBoundaryPolicyException(
                    "$owner has unexpected shape (missing=$missing, unexpected=$unexpected)",
                )
            }
        }

        private fun JSONObject.requireObject(key: String, owner: String): JSONObject =
            opt(key) as? JSONObject
                ?: throw ModuleBoundaryPolicyException("$owner.$key must be an object")

        private fun JSONObject.requireString(key: String, owner: String): String {
            val value = opt(key) as? String
            if (value.isNullOrEmpty()) {
                throw ModuleBoundaryPolicyException("$owner.$key must be a non-empty string")
            }
            return value
        }

        private fun JSONObject.requireBoolean(key: String, owner: String): Boolean =
            opt(key) as? Boolean
                ?: throw ModuleBoundaryPolicyException("$owner.$key must be true or false")

        private fun JSONObject.requireKind(key: String, owner: String): ModuleKind {
            val id = requireString(key, owner)
            return ModuleKind.fromId(id)
                ?: throw ModuleBoundaryPolicyException("$owner.$key has unknown kind '$id'")
        }

        private fun JSONObject.requireUniqueStrings(key: String, owner: String): List<String> {
            val array = opt(key) as? JSONArray
                ?: throw ModuleBoundaryPolicyException("$owner.$key must be an array")
            val values = (0 until array.length()).map { index ->
                val value = array.opt(index) as? String
                if (value.isNullOrEmpty()) {
                    throw ModuleBoundaryPolicyException("$owner.$key[$index] must be a non-empty string")
                }
                value
            }
            if (values.size != values.toSet().size) {
                throw ModuleBoundaryPolicyException("$owner.$key contains duplicates")
            }
            return values
        }
    }
}

/** How the policy governs one module: its kind, whether it is UI, and its layer rule if it has one. */
data class ModuleRule(
    val path: String,
    val kind: ModuleKind,
    val ui: Boolean,
    val layer: LayerRule?,
)

class ModuleBoundaryPolicyException(message: String) : RuntimeException(message)
