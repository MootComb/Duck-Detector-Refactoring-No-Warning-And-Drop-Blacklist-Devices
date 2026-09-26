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
    val appliesCompose: Boolean,
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
        val directionIndex = policy.directionIndex()
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
            errors += validateLayers(policy, group, layers, directionIndex)
        }
        (policy.jvmForbiddenDependencies + policy.uiOnlyDependencies)
            .filter { it.count { character -> character == ':' } != 1 }
            .forEach { pattern -> errors += "artifact pattern '$pattern' must be group:name" }

        policy.members.forEach { (path, member) ->
            errors += validateMemberShape(policy, path, directionIndex)
            val source = requireNotNull(policy.classify(path))
            member.allowedProjectDependencies.filterNot(::isPattern).forEach { target ->
                val targetRule = policy.classify(target)
                when {
                    target == path -> errors += "$path lists itself as a dependency"
                    targetRule == null -> errors += "$path allows unknown module $target"
                    else -> errors += edgeErrors(policy, source, targetRule, directionIndex)
                }
            }
            member.allowedProjectDependencies.filter(::isPattern).filterNot { it.startsWith(":") }.forEach { pattern ->
                errors += "$path allows malformed pattern '$pattern'"
            }
        }
        errors += findMemberCycles(policy)
        return errors
    }

    fun validateMembership(policy: ModuleBoundaryPolicy, includedProjects: Set<String>): List<String> {
        val unclassified = includedProjects.filter { policy.classify(it) == null }.sorted()
            .map { "$it is included in the build but not classified by the boundary policy" }
        val missing = (policy.members.keys - includedProjects).sorted()
            .map { "$it is classified in the boundary policy but not included in the build" }
        return unclassified + missing
    }

    fun validateProject(policy: ModuleBoundaryPolicy, facts: ProjectFacts): List<String> {
        val rule = policy.classify(facts.path)
            ?: return listOf("${facts.path} is not classified by the boundary policy")
        val errors = mutableListOf<String>()
        if (facts.appliedKind != rule.kind) {
            errors += "${facts.path} is classified as ${rule.kind.id} but applies " +
                (facts.appliedKind?.id ?: "no recognised module plugin")
        }
        if (facts.appliesCompose && !rule.ui) {
            errors += "${facts.path} is not a UI module but applies the Compose compiler"
        }
        val directionIndex = policy.directionIndex()
        facts.projectDependencies.toSortedMap().forEach { (configuration, targets) ->
            targets.sorted().forEach { target ->
                val targetRule = policy.classify(target)
                if (targetRule == null) {
                    errors += "${facts.path} depends on $target through '$configuration', " +
                        "which the boundary policy does not classify"
                } else {
                    errors += allowanceErrors(policy, rule, targetRule, configuration) +
                        edgeErrors(policy, rule, targetRule, directionIndex)
                }
            }
        }
        errors += forbiddenArtifacts(policy, facts, rule)
        return errors
    }

    private fun validateLayers(
        policy: ModuleBoundaryPolicy,
        group: String,
        layers: Map<String, LayerRule>,
        directionIndex: Map<String, Int>,
    ): List<String> {
        val errors = mutableListOf<String>()
        if (group !in directionIndex) {
            errors += "layered group $group is not in dependency_direction"
        }
        layers.forEach { (layer, rule) ->
            if (rule.kind == ModuleKind.ANDROID_APPLICATION) {
                errors += "layer $group:$layer is an application but only ${policy.compositionRoot} may be one"
            }
            (rule.mayDependOn - layers.keys).forEach { target ->
                errors += "layer $group:$layer may depend on unknown layer $target"
            }
            rule.mayUse.forEach { pattern ->
                when {
                    !pattern.startsWith(":") -> errors += "layer $group:$layer uses malformed pattern '$pattern'"
                    ModulePath(pattern).group == group ->
                        errors += "layer $group:$layer uses '$pattern'; layers reach their own unit through may_depend_on"
                }
            }
        }
        errors += findLayerCycles(group, layers)
        return errors
    }

    private fun validateMemberShape(
        policy: ModuleBoundaryPolicy,
        path: String,
        directionIndex: Map<String, Int>,
    ): List<String> {
        if (path == policy.compositionRoot) {
            return emptyList()
        }
        val modulePath = ModulePath(path)
        return when {
            modulePath.group !in directionIndex ->
                listOf("$path belongs to group ${modulePath.group}, which is not in dependency_direction")

            modulePath.group in policy.groupLayers ->
                listOf("$path belongs to layered group ${modulePath.group}, whose modules follow its layer rules")

            modulePath.depth != 2 -> listOf("$path must have the form ${modulePath.group}:<unit>")
            else -> emptyList()
        }
    }

    /** Whether the source's own rule admits the dependency at all. */
    private fun allowanceErrors(
        policy: ModuleBoundaryPolicy,
        source: ModuleRule,
        target: ModuleRule,
        configuration: String,
    ): List<String> {
        val layer = source.layer
        if (layer == null) {
            val allowed = policy.members.getValue(source.path).allowedProjectDependencies
            return if (allowed.any { globToRegex(it).matches(target.path) }) {
                emptyList()
            } else {
                listOf(
                    "${source.path} depends on ${target.path} through '$configuration', " +
                        "which the boundary policy does not allow",
                )
            }
        }
        val from = ModulePath(source.path)
        val to = ModulePath(target.path)
        if (from.group == to.group && from.unit == to.unit) {
            return if (to.layer in layer.mayDependOn) {
                emptyList()
            } else {
                listOf(
                    "${source.path} may not depend on ${target.path}: '${from.layer}' layers may only " +
                        "depend on ${layer.mayDependOn.sorted()} of their own unit",
                )
            }
        }
        if (from.group == to.group) {
            // Direction and isolation report edges between units of the same group.
            return emptyList()
        }
        return if (layer.mayUse.any { globToRegex(it).matches(target.path) }) {
            emptyList()
        } else {
            listOf(
                "${source.path} may not depend on ${target.path}: '${from.layer}' layers of ${from.group} " +
                    "may only use ${layer.mayUse.sorted()} outside their unit",
            )
        }
    }

    /** Structural rules every edge obeys, whoever declares it. */
    private fun edgeErrors(
        policy: ModuleBoundaryPolicy,
        source: ModuleRule,
        target: ModuleRule,
        directionIndex: Map<String, Int>,
    ): List<String> {
        val errors = mutableListOf<String>()
        if (target.path == policy.compositionRoot) {
            errors += "${source.path} may not depend on the composition root ${target.path}"
            return errors
        }
        val from = ModulePath(source.path)
        val to = ModulePath(target.path)
        val sourceIndex = if (source.path == policy.compositionRoot) -1 else directionIndex[from.group]
        val destinationIndex = directionIndex[to.group]
        if (sourceIndex != null && destinationIndex != null && destinationIndex < sourceIndex) {
            errors += "${source.path} may not depend on ${target.path}: dependencies point from " +
                policy.dependencyDirection.joinToString(" to ")
        }
        if (from.group == to.group && from.group in policy.isolatedGroups && from.unit != to.unit) {
            errors += "${source.path} may not depend on ${target.path}: units of ${from.group} are isolated from each other"
        }
        if (source.kind == ModuleKind.JVM && target.kind != ModuleKind.JVM) {
            errors += "${source.path} is a pure JVM module and may not depend on ${target.kind.id} ${target.path}"
        }
        if (!source.ui && target.ui) {
            errors += "${source.path} is not a UI module and may not depend on the UI module ${target.path}"
        }
        return errors
    }

    private fun forbiddenArtifacts(policy: ModuleBoundaryPolicy, facts: ProjectFacts, rule: ModuleRule): List<String> {
        val jvmForbidden = policy.jvmForbiddenDependencies.map(::globToRegex)
        val uiOnly = policy.uiOnlyDependencies.map(::globToRegex)
        val errors = mutableListOf<String>()
        facts.externalDependencies.toSortedMap().forEach { (configuration, coordinates) ->
            coordinates.sorted().forEach { coordinate ->
                if (rule.kind == ModuleKind.JVM && jvmForbidden.any { it.matches(coordinate) }) {
                    errors += "${facts.path} is a pure JVM module but depends on Android artifact " +
                        "$coordinate through '$configuration'"
                }
                if (!rule.ui && uiOnly.any { it.matches(coordinate) }) {
                    errors += "${facts.path} is not a UI module but depends on UI artifact " +
                        "$coordinate through '$configuration'"
                }
            }
        }
        return errors
    }

    private fun findMemberCycles(policy: ModuleBoundaryPolicy): List<String> {
        val edges = policy.members.mapValues { (_, member) ->
            member.allowedProjectDependencies.filterNot(::isPattern).filter { it in policy.members }.sorted()
        }
        return findCycles(edges.keys.sorted()) { edges[it].orEmpty() }
    }

    private fun findLayerCycles(group: String, layers: Map<String, LayerRule>): List<String> =
        findCycles(layers.keys.sorted()) { layer ->
            layers[layer]?.mayDependOn?.sorted().orEmpty()
        }.map { "layers of $group form a $it" }

    private fun findCycles(nodes: List<String>, next: (String) -> List<String>): List<String> {
        val visiting = mutableSetOf<String>()
        val visited = mutableSetOf<String>()
        val errors = mutableListOf<String>()

        fun visit(node: String, trail: List<String>) {
            if (node in visited) {
                return
            }
            if (!visiting.add(node)) {
                errors += "dependency cycle: ${(trail.dropWhile { it != node } + node).joinToString(" -> ")}"
                return
            }
            next(node).forEach { visit(it, trail + node) }
            visiting.remove(node)
            visited.add(node)
        }

        nodes.forEach { visit(it, emptyList()) }
        return errors
    }

    private fun ModuleBoundaryPolicy.directionIndex(): Map<String, Int> =
        dependencyDirection.withIndex().associate { it.value to it.index }

    private fun isPattern(value: String): Boolean = '*' in value

    private fun globToRegex(pattern: String): Regex =
        Regex(pattern.split("*").joinToString(".*") { Regex.escape(it) })
}
