/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

package com.eltavine.duckdetector.features.rootmanagers.domain

/** Field-by-field comparison of one observed app with one family signature. */
internal object RootManagerAnchorMatcher {

    fun matchedAnchors(app: ObservedApp, signature: RootManagerSignature): Set<RootManagerAnchor> {
        val anchors = mutableSetOf<RootManagerAnchor>()
        if (app.signingCertificates.any { it in signature.signingCertificates }) {
            anchors += RootManagerAnchor.SIGNING_CERTIFICATE
        }
        if (app.nativePayloads.any { it in signature.nativePayloads }) {
            anchors += RootManagerAnchor.NATIVE_PAYLOAD
        }
        if (signature.packageNames.any { app.packageName.isSameOrUnder(it) }) {
            anchors += RootManagerAnchor.PACKAGE_NAME
        }
        val applicationClass = app.applicationClassName
        if (applicationClass.matchesFamilyClass(signature.applicationClassSuffixes, signature.codeNamespaces)) {
            anchors += RootManagerAnchor.APPLICATION_CLASS
        } else if (applicationClass != null && signature.genericApplicationClassSuffixes.any { applicationClass.endsWith(it) }) {
            anchors += RootManagerAnchor.APPLICATION_CLASS_NAME
        }
        if (app.zygotePreloadName.matchesFamilyClass(signature.zygotePreloadNameSuffixes, signature.codeNamespaces)) {
            anchors += RootManagerAnchor.ZYGOTE_PRELOAD
        }
        val label = app.label
        if (label != null && signature.labelPrefixes.any { label.startsWith(it) }) {
            anchors += RootManagerAnchor.LABEL
        }
        val component = app.componentClassName
        if (component != null && signature.launcherClassSuffixes.any { component.endsWith(it) }) {
            anchors += RootManagerAnchor.LAUNCHER_CLASS
        }
        return anchors
    }

    /** How many manifest class names sit inside the family's code namespace; it only ranks forks. */
    fun namespaceHits(app: ObservedApp, signature: RootManagerSignature): Int =
        listOfNotNull(app.applicationClassName, app.zygotePreloadName, app.componentClassName)
            .count { name -> signature.codeNamespaces.any { name.isUnder(it) } }

    fun longestLabelPrefix(app: ObservedApp, signature: RootManagerSignature): Int {
        val label = app.label ?: return 0
        return signature.labelPrefixes.filter { label.startsWith(it) }.maxOfOrNull { it.length } ?: 0
    }

    // The family's own class name in any namespace, or any class inside the family's namespace.
    private fun String?.matchesFamilyClass(suffixes: Set<String>, namespaces: Set<String>): Boolean {
        val name = this ?: return false
        return suffixes.any { name.endsWith(it) } || namespaces.any { name.isUnder(it) }
    }

    private fun String.isSameOrUnder(prefix: String): Boolean = this == prefix || isUnder(prefix)

    private fun String.isUnder(prefix: String): Boolean = startsWith("$prefix.")
}
