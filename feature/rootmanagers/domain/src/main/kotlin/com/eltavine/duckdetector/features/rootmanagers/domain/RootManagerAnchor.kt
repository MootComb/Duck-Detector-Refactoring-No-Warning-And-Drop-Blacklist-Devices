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
 * One field of an installed app that a family signature can match, and how much a match proves.
 *
 * The signing certificate is cryptographic: it is the key the family's own kernel checks, so a
 * match proves the app was signed by that family's manager key and needs no corroboration. The
 * other strong anchors survive a rename but are names, so they gain high confidence only alongside
 * a second field. Weak anchors are family words or conventional slots an unrelated app could carry.
 */
enum class RootManagerAnchor(
    val displayName: String,
    val strong: Boolean,
    val cryptographic: Boolean = false,
) {
    /** The first v2 signer certificate, compared by length and SHA-256 as the family kernel does. */
    SIGNING_CERTIFICATE("signing certificate", strong = true, cryptographic = true),

    /** A family daemon or tool the manager ships as a native library and executes, such as `libksud.so`. */
    NATIVE_PAYLOAD("native payload", strong = true),

    /** `ApplicationInfo.packageName`: the family's default package name, or a surviving namespace. */
    PACKAGE_NAME("package name", strong = true),

    /** `ApplicationInfo.className`: the app's `Application` class, such as `...KernelSUApplication`. */
    APPLICATION_CLASS("application class", strong = true),

    /** A family's `Application` simple name outside its namespace, generic enough to need company. */
    APPLICATION_CLASS_NAME("application class name", strong = false),

    /** The manifest `android:zygotePreloadName`, such as `...magica.AppZygotePreload`. */
    ZYGOTE_PRELOAD("zygote preload", strong = true),

    LABEL("label", strong = false),

    LAUNCHER_CLASS("launcher class", strong = false),
}
