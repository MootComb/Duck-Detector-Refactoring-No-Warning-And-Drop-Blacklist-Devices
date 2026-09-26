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

#include "preload/preload_extras.h"

#include <cstdint>
#include <string>

namespace {

    void put_boolean_extra(JNIEnv *env, jobject intent, jclass intentClass, const char *key,
                           bool value) {
        jmethodID putBooleanExtra = env->GetMethodID(
                intentClass,
                "putExtra",
                "(Ljava/lang/String;Z)Landroid/content/Intent;"
        );
        if (putBooleanExtra == nullptr) {
            return;
        }
        jstring keyString = env->NewStringUTF(key);
        env->CallObjectMethod(intent, putBooleanExtra, keyString, static_cast<jboolean>(value));
        env->DeleteLocalRef(keyString);
    }

    void put_long_extra(JNIEnv *env, jobject intent, jclass intentClass, const char *key,
                        std::int64_t value) {
        jmethodID putLongExtra = env->GetMethodID(
                intentClass,
                "putExtra",
                "(Ljava/lang/String;J)Landroid/content/Intent;"
        );
        if (putLongExtra == nullptr) {
            return;
        }
        jstring keyString = env->NewStringUTF(key);
        env->CallObjectMethod(intent, putLongExtra, keyString, static_cast<jlong>(value));
        env->DeleteLocalRef(keyString);
    }

    void put_string_extra(JNIEnv *env, jobject intent, jclass intentClass, const char *key,
                          const std::string &value) {
        jmethodID putStringExtra = env->GetMethodID(
                intentClass,
                "putExtra",
                "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;"
        );
        if (putStringExtra == nullptr) {
            return;
        }
        jstring keyString = env->NewStringUTF(key);
        jstring valueString = env->NewStringUTF(value.c_str());
        env->CallObjectMethod(intent, putStringExtra, keyString, valueString);
        env->DeleteLocalRef(keyString);
        env->DeleteLocalRef(valueString);
    }

}  // namespace

namespace duckdetector::preload {

    void attach_preload_extras(
            JNIEnv *env,
            jobject intent,
            jclass intentClass,
            const duckdetector::preload::EarlyMountPreloadResult &result
    ) {
        put_boolean_extra(env, intent, intentClass, "early_detection_has_run", true);
        put_boolean_extra(env, intent, intentClass, "early_detection_detected", result.detected);
        put_string_extra(env, intent, intentClass, "early_detection_method",
                         result.detectionMethod);
        put_string_extra(env, intent, intentClass, "early_detection_details", result.details);
        put_boolean_extra(
                env,
                intent,
                intentClass,
                "early_preload_context_valid",
                duckdetector::preload::is_preload_context_valid()
        );
        put_boolean_extra(env, intent, intentClass, "early_futile_hide", result.futileHideDetected);
        put_boolean_extra(env, intent, intentClass, "early_mnt_strings", result.mntStringsDetected);
        put_boolean_extra(env, intent, intentClass, "early_mount_id_gap",
                          result.mountIdGapDetected);
        put_boolean_extra(env, intent, intentClass, "early_minor_dev_gap",
                          result.minorDevGapDetected);
        put_boolean_extra(env, intent, intentClass, "early_peer_group_gap",
                          result.peerGroupGapDetected);
        put_long_extra(env, intent, intentClass, "early_ns_mnt_ctime_delta_ns",
                       result.nsMntCtimeDeltaNs);
        put_long_extra(env, intent, intentClass, "early_mountinfo_ctime_delta_ns",
                       result.mountInfoCtimeDeltaNs);
        put_string_extra(env, intent, intentClass, "early_mnt_strings_source",
                         result.mntStringsSource);
        put_string_extra(env, intent, intentClass, "early_mnt_strings_target",
                         result.mntStringsTarget);
        put_string_extra(env, intent, intentClass, "early_mnt_strings_fs", result.mntStringsFs);
    }

    void attach_virtualization_preload_extras(
            JNIEnv *env,
            jobject intent,
            jclass intentClass,
            const duckdetector::preload::virtualization::EarlyVirtualizationResult &result
    ) {
        put_boolean_extra(env, intent, intentClass, "early_virtualization_has_run", true);
        put_boolean_extra(env, intent, intentClass, "early_virtualization_detected",
                          result.detected);
        put_string_extra(env, intent, intentClass, "early_virtualization_method",
                         result.detectionMethod);
        put_string_extra(env, intent, intentClass, "early_virtualization_details", result.details);
        put_boolean_extra(
                env,
                intent,
                intentClass,
                "early_virtualization_context_valid",
                duckdetector::preload::virtualization::is_preload_context_valid()
        );
        put_boolean_extra(env, intent, intentClass, "early_virtualization_qemu_property",
                          result.qemuPropertyDetected);
        put_boolean_extra(env, intent, intentClass, "early_virtualization_emulator_hardware",
                          result.emulatorHardwareDetected);
        put_boolean_extra(env, intent, intentClass, "early_virtualization_device_node",
                          result.deviceNodeDetected);
        put_boolean_extra(env, intent, intentClass, "early_virtualization_avf_runtime",
                          result.avfRuntimeDetected);
        put_boolean_extra(env, intent, intentClass, "early_virtualization_authfs_runtime",
                          result.authfsRuntimeDetected);
        put_boolean_extra(env, intent, intentClass, "early_virtualization_native_bridge",
                          result.nativeBridgeDetected);
        put_string_extra(env, intent, intentClass, "early_virtualization_mount_namespace_inode",
                         result.mountNamespaceInode);
        put_string_extra(env, intent, intentClass, "early_virtualization_apex_mount_key",
                         result.apexMountKey);
        put_string_extra(env, intent, intentClass, "early_virtualization_system_mount_key",
                         result.systemMountKey);
        put_string_extra(env, intent, intentClass, "early_virtualization_vendor_mount_key",
                         result.vendorMountKey);
    }

}  // namespace duckdetector::preload
