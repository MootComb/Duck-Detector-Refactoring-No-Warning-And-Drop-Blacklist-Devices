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

package com.eltavine.duckdetector.features.selinux.domain

object SelinuxContextValidityLabels {
    const val METHOD_LABEL = "Context validity oracle"
    const val BITPAIR_CLEAN = "00"
    const val BITPAIR_KSU_PRESENT = "11"
    const val BITPAIR_AMBIGUOUS = "01/10"
    const val BITPAIR_SELF_TEST_FAILED = "Self-test failed"
    const val BITPAIR_UNSUPPORTED = "Unsupported"
}

object SelinuxProcAttrCurrentLabels {
    const val METHOD_LABEL = "app_zygote attr/current write"
    const val STATUS_CLEAN = "Normal EINVAL"
    const val STATUS_UNSUPPORTED = "Unsupported"
}

object SelinuxPolicyloadSeqnoLabels {
    const val METHOD_LABEL = "App-zygote seqno oracle"
    const val STATUS_CLEAN = "Clean"
    const val STATUS_SUSPICIOUS = "Seqno split"
    const val STATUS_INCONCLUSIVE = "Info"
    const val STATUS_UNAVAILABLE = "Unavailable"
}
