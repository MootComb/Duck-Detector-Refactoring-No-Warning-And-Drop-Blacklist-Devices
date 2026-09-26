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

package com.eltavine.duckdetector.core.evidence

/**
 * Marks a value type of the SDK contract. Poko generates its `equals`, `hashCode` and `toString` from
 * the primary constructor's properties, as for a data class, but no `copy` or `componentN`: their
 * signatures would change whenever a property is added, breaking hosts compiled against an earlier
 * release. A module that declares such types applies `duckdetector.contract-values`.
 */
@Retention(AnnotationRetention.SOURCE)
@Target(AnnotationTarget.CLASS)
public annotation class ContractValue
