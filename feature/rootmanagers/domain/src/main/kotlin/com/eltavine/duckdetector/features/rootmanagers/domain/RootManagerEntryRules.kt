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

/**
 * Turns observed apps into root manager entries, matching per field.
 *
 * The fields are independent evidence, so a family counts as matched when any strong field matched,
 * or when two weak fields did. A single weak field never produces an entry: it is a word a launcher
 * label or a conventional `.MainActivity` could carry by coincidence. A signing-certificate match is
 * cryptographic and yields high confidence on its own.
 */
object RootManagerEntryRules {

    fun entries(
        apps: List<ObservedApp>,
        signatures: List<RootManagerSignature> = RootManagerCatalog.signatures,
    ): List<RootManagerEntry> = apps
        .groupBy { app -> app.profileUserId to app.packageName }
        .values
        .mapNotNull { group -> bestEntry(group, signatures) }
        .sortedWith(compareBy<RootManagerEntry>({ it.profileUserId }, { it.family.ordinal }, { it.packageName }))

    fun match(
        app: ObservedApp,
        signatures: List<RootManagerSignature> = RootManagerCatalog.signatures,
    ): RootManagerEntry? = signatures
        .mapIndexedNotNull { index, signature -> candidate(app, signature, index) }
        .maxWithOrNull(CANDIDATE_ORDER)
        ?.toEntry()

    /**
     * One app can be seen once per launcher activity and once through PackageManager. Each launcher
     * view is merged with the PackageManager view, which alone carries the certificate and payloads,
     * and the richest resulting entry stands for the app in that profile.
     */
    private fun bestEntry(group: List<ObservedApp>, signatures: List<RootManagerSignature>): RootManagerEntry? {
        val packageManagerView = group.firstOrNull { it.source == ObservationSource.PACKAGE_MANAGER }
        val launcherViews = group.filter { it.source == ObservationSource.LAUNCHER_APPS }
        val views = when {
            packageManagerView == null -> launcherViews
            launcherViews.isEmpty() -> listOf(packageManagerView)
            else -> launcherViews.map { view -> view.mergedWith(packageManagerView) }
        }
        return views.mapNotNull { view -> match(view, signatures) }.maxWithOrNull(ENTRY_ORDER)
    }

    private fun ObservedApp.mergedWith(packageManagerView: ObservedApp): ObservedApp = copy(
        applicationClassName = applicationClassName ?: packageManagerView.applicationClassName,
        zygotePreloadName = zygotePreloadName ?: packageManagerView.zygotePreloadName,
        signingCertificates = (signingCertificates + packageManagerView.signingCertificates).distinct(),
        nativePayloads = nativePayloads + packageManagerView.nativePayloads,
        sourceDir = sourceDir ?: packageManagerView.sourceDir,
        uid = uid ?: packageManagerView.uid,
        firstInstallTime = firstInstallTime ?: packageManagerView.firstInstallTime,
    )

    private fun candidate(app: ObservedApp, signature: RootManagerSignature, index: Int): Candidate? {
        val anchors = RootManagerAnchorMatcher.matchedAnchors(app, signature)
        if (!isMatch(anchors)) {
            return null
        }
        return Candidate(
            app = app,
            signature = signature,
            anchors = anchors,
            confidence = confidence(anchors),
            index = index,
            namespaceHits = RootManagerAnchorMatcher.namespaceHits(app, signature),
            labelPrefixLength = RootManagerAnchorMatcher.longestLabelPrefix(app, signature),
        )
    }

    private fun isMatch(anchors: Set<RootManagerAnchor>): Boolean =
        anchors.any { it.strong } || anchors.size >= 2

    private fun confidence(anchors: Set<RootManagerAnchor>): RootManagerConfidence = when {
        anchors.any { it.cryptographic } -> RootManagerConfidence.HIGH
        anchors.none { it.strong } -> RootManagerConfidence.LOW
        anchors.size >= 2 -> RootManagerConfidence.HIGH
        else -> RootManagerConfidence.MEDIUM
    }

    /**
     * Ranks the families one app matched, so it becomes a single entry under its best fit. The
     * shared `.KernelSUApplication`, `.magica.AppZygotePreload` and `libksud.so` match every KernelSU
     * fork, so the ranking prefers what separates them: the fork's own manager key, then its package
     * name, then how many class names sit in its code namespace, then the longest label prefix.
     * Remaining ties fall back to catalogue order.
     */
    private val CANDIDATE_ORDER: Comparator<Candidate> =
        compareBy<Candidate> { if (RootManagerAnchor.SIGNING_CERTIFICATE in it.anchors) 1 else 0 }
            .thenBy { if (RootManagerAnchor.PACKAGE_NAME in it.anchors) 1 else 0 }
            .thenBy { it.namespaceHits }
            .thenBy { it.labelPrefixLength }
            .thenBy { it.anchors.size }
            .thenByDescending { it.index }

    // RootManagerConfidence is declared strongest first, so a lower ordinal is the better entry.
    private val ENTRY_ORDER: Comparator<RootManagerEntry> =
        compareBy<RootManagerEntry> { -it.confidence.ordinal }
            .thenBy { it.anchors.size }

    private data class Candidate(
        val app: ObservedApp,
        val signature: RootManagerSignature,
        val anchors: Set<RootManagerAnchor>,
        val confidence: RootManagerConfidence,
        val index: Int,
        val namespaceHits: Int,
        val labelPrefixLength: Int,
    ) {
        fun toEntry(): RootManagerEntry = RootManagerEntry(
            family = signature.family,
            packageName = app.packageName,
            displayName = app.label?.takeIf { it.isNotBlank() } ?: signature.family.displayName,
            profileUserId = app.profileUserId,
            componentClassName = app.componentClassName,
            applicationClassName = app.applicationClassName,
            sourceDir = app.sourceDir,
            uid = app.uid,
            firstInstallTime = app.firstInstallTime,
            anchors = anchors,
            confidence = confidence,
            matchedCertificate = app.signingCertificates.firstOrNull { it in signature.signingCertificates },
            matchedPayloads = app.nativePayloads.intersect(signature.nativePayloads),
            hidesLauncherIcon = app.hidesLauncherIcon,
        )
    }
}
