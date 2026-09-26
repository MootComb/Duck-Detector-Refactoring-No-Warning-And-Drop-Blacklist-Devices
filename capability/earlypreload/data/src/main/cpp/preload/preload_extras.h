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

#pragma once

#include "preload/early_detector.h"
#include "preload/virtualization_early_detector.h"

#include <jni.h>

namespace duckdetector::preload {

    // The extras that carry the early mount evidence to the activity the launcher starts; the
    // activity hands them to DuckDetector.captureLaunchEvidence, which reads them by these keys.
    void attach_preload_extras(
            JNIEnv *env,
            jobject intent,
            jclass intentClass,
            const EarlyMountPreloadResult &result
    );

    // The extras that carry the early virtualization evidence on the same intent.
    void attach_virtualization_preload_extras(
            JNIEnv *env,
            jobject intent,
            jclass intentClass,
            const virtualization::EarlyVirtualizationResult &result
    );

}  // namespace duckdetector::preload
