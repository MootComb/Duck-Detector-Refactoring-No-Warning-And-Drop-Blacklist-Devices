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

    val validMembers: Map<String, Pair<String, List<String>>> = linkedMapOf(
        ":app" to ("android-application" to listOf(":feature:su:ui", ":feature:su:data", ":core:evidence")),
        ":feature:su:domain" to ("jvm" to listOf(":core:evidence")),
        ":feature:su:data" to ("android-library" to listOf(":feature:su:domain", ":capability:probe:android")),
        ":feature:su:presentation" to ("jvm" to listOf(":feature:su:domain", ":core:evidence")),
        ":feature:su:ui" to ("android-library" to listOf(":feature:su:presentation", ":feature:su:domain")),
        ":capability:probe:model" to ("jvm" to emptyList()),
        ":capability:probe:android" to ("android-library" to listOf(":capability:probe:model")),
        ":core:evidence" to ("jvm" to emptyList()),
        ":core:scan" to ("jvm" to listOf(":core:evidence")),
    )

    fun policyJson(
        members: Map<String, Pair<String, List<String>>> = validMembers,
        compositionRoot: String = ":app",
        mutate: (JSONObject) -> Unit = {},
    ): String {
        val document = JSONObject()
        document.put("schema_version", 1)
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
                                .put("domain", layer("jvm"))
                                .put("data", layer("android-library", "domain"))
                                .put("presentation", layer("jvm", "domain"))
                                .put("ui", layer("android-library", "domain", "presentation")),
                        )
                        .put(
                            ":capability",
                            JSONObject()
                                .put("model", layer("jvm"))
                                .put("android", layer("android-library", "model")),
                        ),
                )
                .put("jvm_forbidden_dependencies", JSONArray(listOf("androidx.*:*", "com.google.android.*:*"))),
        )
        val membersObject = JSONObject()
        members.forEach { (path, member) ->
            membersObject.put(
                path,
                JSONObject()
                    .put("kind", member.first)
                    .put("allowed_project_dependencies", JSONArray(member.second)),
            )
        }
        document.put("members", membersObject)
        mutate(document)
        return document.toString(2)
    }

    fun policy(
        members: Map<String, Pair<String, List<String>>> = validMembers,
        compositionRoot: String = ":app",
    ): ModuleBoundaryPolicy = ModuleBoundaryPolicy.parse(policyJson(members, compositionRoot))

    fun withMember(path: String, kind: String, vararg dependencies: String): Map<String, Pair<String, List<String>>> =
        validMembers + (path to (kind to dependencies.toList()))

    private fun layer(kind: String, vararg mayDependOn: String): JSONObject =
        JSONObject().put("kind", kind).put("may_depend_on", JSONArray(mayDependOn.toList()))
}
