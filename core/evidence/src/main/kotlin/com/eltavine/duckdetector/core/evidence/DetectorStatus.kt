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

@ContractValue
public class DetectorStatus(
    public val severity: DetectionSeverity,
    public val infoKind: InfoKind? = null,
) {
    init {
        require(severity == DetectionSeverity.INFO || infoKind == null) {
            "Only INFO status can carry an InfoKind"
        }
    }

    public companion object {
        public fun info(kind: InfoKind): DetectorStatus = DetectorStatus(DetectionSeverity.INFO, kind)
        public fun allClear(): DetectorStatus = DetectorStatus(DetectionSeverity.ALL_CLEAR)
        public fun warning(): DetectorStatus = DetectorStatus(DetectionSeverity.WARNING)
        public fun danger(): DetectorStatus = DetectorStatus(DetectionSeverity.DANGER)
    }
}
