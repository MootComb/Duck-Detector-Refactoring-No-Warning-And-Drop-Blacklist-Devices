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
import org.json.JSONObject

internal object PolicyFixtures {

    data class Member(val kind: String, val ui: Boolean, val dependencies: List<String>)

    /** The composition root and the modules of the one group without layers. */
    val validMembers: Map<String, Member> = linkedMapOf(
        ":app" to Member("android-application", ui = true, listOf(":feature:*:ui", ":feature:*:data", ":core:*")),
        ":core:evidence" to Member("jvm", ui = false, emptyList()),
        ":core:scan" to Member("jvm", ui = false, listOf(":core:evidence")),
        ":core:ui" to Member("android-library", ui = true, listOf(":core:evidence")),
    )

    fun policyJson(
        members: Map<String, Member> = validMembers,
        compositionRoot: String = ":app",
        mutate: (JSONObject) -> Unit = {},
    ): String {
        val document = JSONObject()
        document.put("schema_version", 2)
        document.put(
            "rules",
            JSONObject()
                .put("composition_root", compositionRoot)
                .put("dependency_direction", JSONArray(listOf(":app", ":feature", ":capability", ":core")))
                .put("isolated_groups", JSONArray(listOf(":feature", ":capability")))
                .put(
                    "group_layers",
                    JSONObject()
                        .put(
                            ":feature",
                            JSONObject()
                                .put("domain", layer("jvm", use = listOf(":core:evidence", ":capability:*:model")))
                                .put(
                                    "data",
                                    layer(
                                        "android-library",
                                        "domain",
                                        use = listOf(":core:evidence", ":capability:*:android", ":capability:*:model"),
                                    ),
                                )
                                .put("presentation", layer("jvm", "domain", use = listOf(":core:evidence", ":core:scan")))
                                .put(
                                    "ui",
                                    layer(
                                        "android-library",
                                        "domain",
                                        "presentation",
                                        ui = true,
                                        use = listOf(":core:evidence", ":core:scan", ":core:ui"),
                                    ),
                                ),
                        )
                        .put(
                            ":capability",
                            JSONObject()
                                .put("model", layer("jvm", use = listOf(":core:evidence")))
                                .put("android", layer("android-library", "model", use = listOf(":core:evidence"))),
                        ),
                )
                .put("jvm_forbidden_dependencies", JSONArray(listOf("androidx.*:*", "com.google.android.*:*")))
                .put("ui_only_dependencies", JSONArray(listOf("androidx.compose.*:*"))),
        )
        val membersObject = JSONObject()
        members.forEach { (path, member) ->
            membersObject.put(
                path,
                JSONObject()
                    .put("kind", member.kind)
                    .put("ui", member.ui)
                    .put("allowed_project_dependencies", JSONArray(member.dependencies)),
            )
        }
        document.put("members", membersObject)
        mutate(document)
        return document.toString(2)
    }

    fun policy(
        members: Map<String, Member> = validMembers,
        compositionRoot: String = ":app",
        mutate: (JSONObject) -> Unit = {},
    ): ModuleBoundaryPolicy = ModuleBoundaryPolicy.parse(policyJson(members, compositionRoot, mutate))

    fun withMember(path: String, kind: String, vararg dependencies: String, ui: Boolean = false): Map<String, Member> =
        validMembers + (path to Member(kind, ui, dependencies.toList()))

    /** Replaces one layer rule of [group], for tests about the layer templates themselves. */
    fun withLayer(group: String, layer: String, rule: JSONObject): (JSONObject) -> Unit = { document ->
        document.getJSONObject("rules").getJSONObject("group_layers").getJSONObject(group).put(layer, rule)
    }

    fun layer(
        kind: String,
        vararg mayDependOn: String,
        ui: Boolean = false,
        use: List<String> = emptyList(),
    ): JSONObject = JSONObject()
        .put("kind", kind)
        .put("ui", ui)
        .put("may_depend_on", JSONArray(mayDependOn.toList()))
        .put("may_use", JSONArray(use))
}
