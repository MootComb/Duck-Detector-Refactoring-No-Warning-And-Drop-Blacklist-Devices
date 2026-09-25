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

/** What the build actually declares for one project, gathered after evaluation. */
data class ProjectFacts(
    val path: String,
    val appliedKind: ModuleKind?,
    val projectDependencies: Map<String, Set<String>>,
    val externalDependencies: Map<String, Set<String>>,
)

internal data class ModulePath(val path: String) {
    private val segments = path.removePrefix(":").split(":")
    val group: String = ":" + segments.first()
    val unit: String? = segments.getOrNull(1)
    val layer: String? = segments.getOrNull(2)
    val depth: Int = segments.size
}

object ModuleBoundaryValidator {

    fun validatePolicy(policy: ModuleBoundaryPolicy): List<String> {
        val errors = mutableListOf<String>()
        val directionIndex = policy.dependencyDirection.withIndex().associate { it.value to it.index }
        val root = policy.members[policy.compositionRoot]
        if (root == null) {
            errors += "composition root ${policy.compositionRoot} is not a member"
        } else if (root.kind != ModuleKind.ANDROID_APPLICATION) {
            errors += "composition root ${policy.compositionRoot} must be an ${ModuleKind.ANDROID_APPLICATION.id}"
        }
        policy.members.filter { (path, member) ->
            member.kind == ModuleKind.ANDROID_APPLICATION && path != policy.compositionRoot
        }.keys.forEach { path ->
            errors += "$path is an application but only ${policy.compositionRoot} may be one"
        }
        (policy.isolatedGroups - directionIndex.keys).forEach { group ->
            errors += "isolated group $group is not in dependency_direction"
        }
        policy.groupLayers.forEach { (group, layers) ->
            if (group !in directionIndex) {
                errors += "layered group $group is not in dependency_direction"
            }
            layers.forEach { (layer, rule) ->
                (rule.mayDependOn - layers.keys).forEach { target ->
                    errors += "layer $group:$layer may depend on unknown layer $target"
                }
            }
        }
        policy.jvmForbiddenDependencies.filter { it.count { character -> character == ':' } != 1 }
            .forEach { pattern -> errors += "forbidden dependency pattern '$pattern' must be group:name" }

        policy.members.forEach { (path, member) ->
            errors += validateMemberShape(policy, path, member, directionIndex)
            member.allowedProjectDependencies.forEach { target ->
                val targetMember = policy.members[target]
                if (target == path) {
                    errors += "$path lists itself as a dependency"
                } else if (targetMember == null) {
                    errors += "$path allows unknown member $target"
                } else {
                    errors += validateEdge(policy, path, member, target, targetMember, directionIndex)
                }
            }
        }
        errors += findCycles(policy)
        return errors
    }

    fun validateMembership(policy: ModuleBoundaryPolicy, includedProjects: Set<String>): List<String> {
        val unclassified = (includedProjects - policy.members.keys).sorted()
            .map { "$it is included in the build but not classified in the boundary policy" }
        val missing = (policy.members.keys - includedProjects).sorted()
            .map { "$it is classified in the boundary policy but not included in the build" }
        return unclassified + missing
    }

    fun validateProject(policy: ModuleBoundaryPolicy, facts: ProjectFacts): List<String> {
        val member = policy.members[facts.path]
            ?: return listOf("${facts.path} is not classified in the boundary policy")
        val errors = mutableListOf<String>()
        if (facts.appliedKind != member.kind) {
            errors += "${facts.path} is classified as ${member.kind.id} but applies " +
                (facts.appliedKind?.id ?: "no recognised module plugin")
        }
        facts.projectDependencies.toSortedMap().forEach { (configuration, targets) ->
            targets.sorted().filter { it !in member.allowedProjectDependencies }.forEach { target ->
                errors += "${facts.path} depends on $target through '$configuration', " +
                    "which the boundary policy does not allow"
            }
        }
        if (member.kind == ModuleKind.JVM) {
            val forbidden = policy.jvmForbiddenDependencies.map(::globToRegex)
            facts.externalDependencies.toSortedMap().forEach { (configuration, coordinates) ->
                coordinates.sorted().filter { coordinate -> forbidden.any { it.matches(coordinate) } }
                    .forEach { coordinate ->
                        errors += "${facts.path} is a pure JVM module but depends on Android artifact " +
                            "$coordinate through '$configuration'"
                    }
            }
        }
        return errors
    }

    private fun validateMemberShape(
        policy: ModuleBoundaryPolicy,
        path: String,
        member: ModuleMember,
        directionIndex: Map<String, Int>,
    ): List<String> {
        if (path == policy.compositionRoot) {
            return emptyList()
        }
        val modulePath = ModulePath(path)
        if (modulePath.group !in directionIndex) {
            return listOf("$path belongs to group ${modulePath.group}, which is not in dependency_direction")
        }
        val layers = policy.groupLayers[modulePath.group]
        if (layers == null) {
            return if (modulePath.depth == 2) emptyList() else listOf("$path must have the form ${modulePath.group}:<unit>")
        }
        val layer = modulePath.layer
        val rule = layers[layer]
        return when {
            modulePath.depth != 3 || layer == null ->
                listOf("$path must have the form ${modulePath.group}:<unit>:<layer>")

            rule == null -> listOf("$path uses layer '$layer', which is not declared for ${modulePath.group}")
            rule.kind != member.kind ->
                listOf("$path is a ${member.kind.id} but ${modulePath.group} '$layer' layers must be ${rule.kind.id}")

            else -> emptyList()
        }
    }

    private fun validateEdge(
        policy: ModuleBoundaryPolicy,
        path: String,
        member: ModuleMember,
        target: String,
        targetMember: ModuleMember,
        directionIndex: Map<String, Int>,
    ): List<String> {
        val errors = mutableListOf<String>()
        if (target == policy.compositionRoot) {
            errors += "$path may not depend on the composition root $target"
            return errors
        }
        val source = ModulePath(path)
        val destination = ModulePath(target)
        val sourceIndex = if (path == policy.compositionRoot) -1 else directionIndex[source.group]
        val destinationIndex = directionIndex[destination.group]
        if (sourceIndex != null && destinationIndex != null && destinationIndex < sourceIndex) {
            errors += "$path may not depend on $target: dependencies point from " +
                "${policy.dependencyDirection.joinToString(" to ")}"
        }
        if (source.group == destination.group && source.group in policy.isolatedGroups &&
            source.unit != destination.unit
        ) {
            errors += "$path may not depend on $target: units of ${source.group} are isolated from each other"
        }
        val layers = policy.groupLayers[source.group]
        if (layers != null && source.group == destination.group && source.unit == destination.unit) {
            val allowed = layers[source.layer]?.mayDependOn.orEmpty()
            if (destination.layer !in allowed) {
                errors += "$path may not depend on $target: '${source.layer}' layers may only depend on $allowed"
            }
        }
        if (member.kind == ModuleKind.JVM && targetMember.kind != ModuleKind.JVM) {
            errors += "$path is a pure JVM module and may not depend on ${targetMember.kind.id} $target"
        }
        return errors
    }

    private fun findCycles(policy: ModuleBoundaryPolicy): List<String> {
        val visiting = mutableSetOf<String>()
        val visited = mutableSetOf<String>()
        val errors = mutableListOf<String>()

        fun visit(path: String, trail: List<String>) {
            if (path in visited) {
                return
            }
            if (!visiting.add(path)) {
                errors += "dependency cycle: ${(trail.dropWhile { it != path } + path).joinToString(" -> ")}"
                return
            }
            policy.members[path]?.allowedProjectDependencies?.sorted()?.forEach { visit(it, trail + path) }
            visiting.remove(path)
            visited.add(path)
        }

        policy.members.keys.sorted().forEach { visit(it, emptyList()) }
        return errors
    }

    private fun globToRegex(pattern: String): Regex =
        Regex(pattern.split("*").joinToString(".*") { Regex.escape(it) })
}
