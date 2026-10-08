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
 * A root manager family, kept separate from the others by its own catalogue entry.
 *
 * KernelSU and its forks name their `Application` class `…KernelSUApplication` and APatch names its
 * own `…APApplication`, so a rename can leave that class naming a family the package name no longer
 * does. Each KernelSU fork's kernel trusts its own manager key, which is what separates the forks
 * once their shared class names stop doing so.
 */
enum class RootManagerFamily(
    val displayName: String,
) {
    KERNEL_SU("KernelSU"),
    KERNEL_SU_NEXT("KernelSU-Next"),
    SUKI_SU("SukiSU Ultra"),

    /** ReSukiSU continues upstream as BakaSU, which still ships the `com.resukisu.resukisu` package. */
    RE_SUKI_SU("ReSukiSU (BakaSU)"),
    APATCH("APatch"),
    SK_ROOT("SKRoot"),
    MAGISK("Magisk"),
}
