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

#include "preload/early_detector.h"
#include "preload/virtualization_early_detector.h"

#include <jni.h>

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyMountPreloadBridge_nativeHasEarlyDetectionRun(
        JNIEnv *,
        jobject
) {
    return duckdetector::preload::has_early_detection_run();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyMountPreloadBridge_nativeIsPreloadContextValid(
        JNIEnv *,
        jobject
) {
    return duckdetector::preload::is_preload_context_valid();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyMountPreloadBridge_nativeWasDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return result != nullptr ? result->detected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyMountPreloadBridge_nativeWasFutileHideDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return result != nullptr ? result->futileHideDetected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyMountPreloadBridge_nativeWasMinorDevGapDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return result != nullptr ? result->minorDevGapDetected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyMountPreloadBridge_nativeWasMountIdGapDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return result != nullptr ? result->mountIdGapDetected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyMountPreloadBridge_nativeWasMntStringsDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return result != nullptr ? result->mntStringsDetected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyMountPreloadBridge_nativeWasPeerGroupGapDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return result != nullptr ? result->peerGroupGapDetected : false;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyMountPreloadBridge_nativeGetDetectionMethod(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->detectionMethod.c_str() : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyMountPreloadBridge_nativeGetDetails(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->details.c_str() : "");
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyMountPreloadBridge_nativeGetFindings(
        JNIEnv *env,
        jobject
) {
    jclass stringClass = env->FindClass("java/lang/String");
    const auto *result = duckdetector::preload::get_stored_result();
    if (result == nullptr || result->findings.empty()) {
        return env->NewObjectArray(0, stringClass, nullptr);
    }

    jobjectArray array = env->NewObjectArray(
            static_cast<jsize>(result->findings.size()),
            stringClass,
            nullptr
    );
    for (std::size_t index = 0; index < result->findings.size(); ++index) {
        jstring item = env->NewStringUTF(result->findings[index].c_str());
        env->SetObjectArrayElement(array, static_cast<jsize>(index), item);
        env->DeleteLocalRef(item);
    }
    return array;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyMountPreloadBridge_nativeGetNsMntCtimeDeltaNs(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return result != nullptr ? static_cast<jlong>(result->nsMntCtimeDeltaNs) : 0;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyMountPreloadBridge_nativeGetMountInfoCtimeDeltaNs(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return result != nullptr ? static_cast<jlong>(result->mountInfoCtimeDeltaNs) : 0;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyMountPreloadBridge_nativeGetMntStringsSource(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->mntStringsSource.c_str() : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyMountPreloadBridge_nativeGetMntStringsTarget(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->mntStringsTarget.c_str() : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyMountPreloadBridge_nativeGetMntStringsFs(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->mntStringsFs.c_str() : "");
}

extern "C" JNIEXPORT void JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyMountPreloadBridge_nativeReset(
        JNIEnv *,
        jobject
) {
    duckdetector::preload::reset_early_detection();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyVirtualizationPreloadBridge_nativeHasEarlyDetectionRun(
        JNIEnv *,
        jobject
) {
    return duckdetector::preload::virtualization::has_early_detection_run();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyVirtualizationPreloadBridge_nativeIsPreloadContextValid(
        JNIEnv *,
        jobject
) {
    return duckdetector::preload::virtualization::is_preload_context_valid();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyVirtualizationPreloadBridge_nativeWasDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return result != nullptr ? result->detected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyVirtualizationPreloadBridge_nativeWasQemuPropertyDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return result != nullptr ? result->qemuPropertyDetected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyVirtualizationPreloadBridge_nativeWasEmulatorHardwareDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return result != nullptr ? result->emulatorHardwareDetected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyVirtualizationPreloadBridge_nativeWasDeviceNodeDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return result != nullptr ? result->deviceNodeDetected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyVirtualizationPreloadBridge_nativeWasAvfRuntimeDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return result != nullptr ? result->avfRuntimeDetected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyVirtualizationPreloadBridge_nativeWasAuthfsRuntimeDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return result != nullptr ? result->authfsRuntimeDetected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyVirtualizationPreloadBridge_nativeWasNativeBridgeDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return result != nullptr ? result->nativeBridgeDetected : false;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyVirtualizationPreloadBridge_nativeGetDetectionMethod(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->detectionMethod.c_str() : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyVirtualizationPreloadBridge_nativeGetDetails(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->details.c_str() : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyVirtualizationPreloadBridge_nativeGetMountNamespaceInode(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->mountNamespaceInode.c_str() : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyVirtualizationPreloadBridge_nativeGetApexMountKey(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->apexMountKey.c_str() : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyVirtualizationPreloadBridge_nativeGetSystemMountKey(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->systemMountKey.c_str() : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyVirtualizationPreloadBridge_nativeGetVendorMountKey(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->vendorMountKey.c_str() : "");
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyVirtualizationPreloadBridge_nativeGetFindings(
        JNIEnv *env,
        jobject
) {
    jclass stringClass = env->FindClass("java/lang/String");
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    if (result == nullptr || result->findings.empty()) {
        return env->NewObjectArray(0, stringClass, nullptr);
    }

    jobjectArray array = env->NewObjectArray(
            static_cast<jsize>(result->findings.size()),
            stringClass,
            nullptr
    );
    for (std::size_t index = 0; index < result->findings.size(); ++index) {
        jstring item = env->NewStringUTF(result->findings[index].c_str());
        env->SetObjectArrayElement(array, static_cast<jsize>(index), item);
        env->DeleteLocalRef(item);
    }
    return array;
}

extern "C" JNIEXPORT void JNICALL
Java_com_eltavine_duckdetector_capability_earlypreload_data_EarlyVirtualizationPreloadBridge_nativeReset(
        JNIEnv *,
        jobject
) {
    duckdetector::preload::virtualization::reset_early_detection();
}
