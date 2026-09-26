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
#include "preload/preload_extras.h"
#include "preload/virtualization_early_detector.h"

#include <android/log.h>
#include <android/native_activity.h>
#include <jni.h>

#include <cstdint>
#include <string>
#include <time.h>

#define LOG_TAG "MountPreloadEntry"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

    constexpr std::int64_t kSecToNs = 1000000000LL;
    constexpr std::int64_t kDuplicateLaunchWindowNs = kSecToNs;
    constexpr const char *kLaunchActivityMetaData = "com.eltavine.duckdetector.launch_activity";

    std::int64_t g_lastHandoffNs = 0;

    std::int64_t monotonic_now_ns() {
        struct timespec now{};
        clock_gettime(CLOCK_MONOTONIC, &now);
        return (static_cast<std::int64_t>(now.tv_sec) * kSecToNs) + now.tv_nsec;
    }

    void finish_activity(JNIEnv *env, jobject activity) {
        jclass activityClass = env->GetObjectClass(activity);
        if (activityClass == nullptr) {
            return;
        }
        jmethodID finish = env->GetMethodID(activityClass, "finish", "()V");
        if (finish != nullptr) {
            env->CallVoidMethod(activity, finish);
        }
        env->DeleteLocalRef(activityClass);
    }

    // Each lookup goes through the public declaration, and every failure returns at once, so no
    // JNI call runs with an exception pending; the caller clears it.
    jstring launch_activity_meta_data(JNIEnv *env, jobject activity) {
        jclass activityClass = env->GetObjectClass(activity);
        jmethodID getPackageManager = env->GetMethodID(activityClass, "getPackageManager",
                                                       "()Landroid/content/pm/PackageManager;");
        if (getPackageManager == nullptr) {
            return nullptr;
        }
        jmethodID getComponentName = env->GetMethodID(activityClass, "getComponentName",
                                                      "()Landroid/content/ComponentName;");
        if (getComponentName == nullptr) {
            return nullptr;
        }
        jobject packageManager = env->CallObjectMethod(activity, getPackageManager);
        if (packageManager == nullptr) {
            return nullptr;
        }
        jobject component = env->CallObjectMethod(activity, getComponentName);
        if (component == nullptr) {
            return nullptr;
        }
        jclass packageManagerClass = env->FindClass("android/content/pm/PackageManager");
        if (packageManagerClass == nullptr) {
            return nullptr;
        }
        jmethodID getActivityInfo = env->GetMethodID(
                packageManagerClass,
                "getActivityInfo",
                "(Landroid/content/ComponentName;I)Landroid/content/pm/ActivityInfo;"
        );
        if (getActivityInfo == nullptr) {
            return nullptr;
        }
        constexpr jint GET_META_DATA = 0x00000080;
        jobject activityInfo = env->CallObjectMethod(packageManager, getActivityInfo, component,
                                                     GET_META_DATA);
        if (activityInfo == nullptr) {
            return nullptr;
        }
        jclass itemInfoClass = env->FindClass("android/content/pm/PackageItemInfo");
        if (itemInfoClass == nullptr) {
            return nullptr;
        }
        jfieldID metaDataField = env->GetFieldID(itemInfoClass, "metaData", "Landroid/os/Bundle;");
        if (metaDataField == nullptr) {
            return nullptr;
        }
        jobject metaData = env->GetObjectField(activityInfo, metaDataField);
        if (metaData == nullptr) {
            return nullptr;
        }
        jclass bundleClass = env->FindClass("android/os/BaseBundle");
        if (bundleClass == nullptr) {
            return nullptr;
        }
        jmethodID getString = env->GetMethodID(bundleClass, "getString",
                                               "(Ljava/lang/String;)Ljava/lang/String;");
        if (getString == nullptr) {
            return nullptr;
        }
        jstring key = env->NewStringUTF(kLaunchActivityMetaData);
        if (key == nullptr) {
            return nullptr;
        }
        return static_cast<jstring>(env->CallObjectMethod(metaData, getString, key));
    }

    // The activity the host names in this NativeActivity's <meta-data>, read from the bundle that
    // NativeActivity reads android.app.lib_name from; empty when the entry is absent or unreadable.
    std::string configured_launch_activity(JNIEnv *env, jobject activity) {
        if (env->PushLocalFrame(16) != JNI_OK) {
            env->ExceptionClear();
            return {};
        }
        std::string configured;
        jstring value = launch_activity_meta_data(env, activity);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        } else if (value != nullptr) {
            const char *chars = env->GetStringUTFChars(value, nullptr);
            if (chars != nullptr) {
                configured = chars;
                env->ReleaseStringUTFChars(value, chars);
            }
        }
        env->PopLocalFrame(nullptr);
        return configured;
    }

    void start_launch_activity_and_finish(JNIEnv *env, jobject activity) {
        const std::int64_t nowNs = monotonic_now_ns();
        if (g_lastHandoffNs != 0 && (nowNs - g_lastHandoffNs) < kDuplicateLaunchWindowNs) {
            finish_activity(env, activity);
            return;
        }

        const auto *stored = duckdetector::preload::get_stored_result();
        const duckdetector::preload::EarlyMountPreloadResult emptyResult{};
        const auto &result = stored != nullptr ? *stored : emptyResult;
        const auto *virtualizationStored = duckdetector::preload::virtualization::get_stored_result();
        const duckdetector::preload::virtualization::EarlyVirtualizationResult emptyVirtualizationResult{};
        const auto &virtualizationResult = virtualizationStored != nullptr
                                           ? *virtualizationStored
                                           : emptyVirtualizationResult;

        jclass activityClass = env->GetObjectClass(activity);
        if (activityClass == nullptr) {
            LOGE("Failed to resolve NativeActivity class");
            return;
        }

        jmethodID getPackageName = env->GetMethodID(activityClass, "getPackageName",
                                                    "()Ljava/lang/String;");
        jmethodID startActivity = env->GetMethodID(activityClass, "startActivity",
                                                   "(Landroid/content/Intent;)V");
        jmethodID finish = env->GetMethodID(activityClass, "finish", "()V");
        if (getPackageName == nullptr || startActivity == nullptr || finish == nullptr) {
            LOGE("Failed to resolve NativeActivity methods");
            env->DeleteLocalRef(activityClass);
            return;
        }

        jstring packageName = static_cast<jstring>(env->CallObjectMethod(activity, getPackageName));
        if (packageName == nullptr) {
            LOGE("Failed to read package name");
            env->DeleteLocalRef(activityClass);
            return;
        }

        const char *packageChars = env->GetStringUTFChars(packageName, nullptr);
        const std::string packageNameString(packageChars == nullptr ? "" : packageChars);
        if (packageChars != nullptr) {
            env->ReleaseStringUTFChars(packageName, packageChars);
        }

        jclass intentClass = env->FindClass("android/content/Intent");
        jclass componentNameClass = env->FindClass("android/content/ComponentName");
        if (intentClass == nullptr || componentNameClass == nullptr) {
            LOGE("Failed to resolve Intent/ComponentName");
            env->DeleteLocalRef(packageName);
            env->DeleteLocalRef(activityClass);
            return;
        }

        jmethodID intentInit = env->GetMethodID(intentClass, "<init>", "()V");
        jmethodID addFlags = env->GetMethodID(intentClass, "addFlags",
                                              "(I)Landroid/content/Intent;");
        jmethodID setComponent = env->GetMethodID(
                intentClass,
                "setComponent",
                "(Landroid/content/ComponentName;)Landroid/content/Intent;"
        );
        jmethodID componentInit = env->GetMethodID(
                componentNameClass,
                "<init>",
                "(Ljava/lang/String;Ljava/lang/String;)V"
        );
        if (intentInit == nullptr || addFlags == nullptr || setComponent == nullptr ||
            componentInit == nullptr) {
            LOGE("Failed to resolve Intent/ComponentName methods");
            env->DeleteLocalRef(componentNameClass);
            env->DeleteLocalRef(intentClass);
            env->DeleteLocalRef(packageName);
            env->DeleteLocalRef(activityClass);
            return;
        }

        const std::string configuredActivity = configured_launch_activity(env, activity);
        const std::string launchActivityClassName = configuredActivity.empty()
                                                    ? packageNameString + ".MainActivity"
                                                    : configuredActivity;
        jobject intent = env->NewObject(intentClass, intentInit);
        jstring packageString = env->NewStringUTF(packageNameString.c_str());
        jstring classString = env->NewStringUTF(launchActivityClassName.c_str());
        jobject component = env->NewObject(componentNameClass, componentInit, packageString,
                                           classString);

        env->CallObjectMethod(intent, setComponent, component);
        constexpr int FLAG_ACTIVITY_NEW_TASK = 0x10000000;
        constexpr int FLAG_ACTIVITY_CLEAR_TOP = 0x04000000;
        constexpr int FLAG_ACTIVITY_SINGLE_TOP = 0x20000000;
        env->CallObjectMethod(
                intent,
                addFlags,
                FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_CLEAR_TOP | FLAG_ACTIVITY_SINGLE_TOP
        );

        duckdetector::preload::attach_preload_extras(env, intent, intentClass, result);
        duckdetector::preload::attach_virtualization_preload_extras(env, intent, intentClass, virtualizationResult);

        env->CallVoidMethod(activity, startActivity, intent);
        env->CallVoidMethod(activity, finish);
        g_lastHandoffNs = nowNs;

        env->DeleteLocalRef(component);
        env->DeleteLocalRef(classString);
        env->DeleteLocalRef(packageString);
        env->DeleteLocalRef(intent);
        env->DeleteLocalRef(componentNameClass);
        env->DeleteLocalRef(intentClass);
        env->DeleteLocalRef(packageName);
        env->DeleteLocalRef(activityClass);
    }

    void on_destroy(ANativeActivity *activity) {
        (void) activity;
    }

    void on_start(ANativeActivity *activity) {
        (void) activity;
    }

    void on_resume(ANativeActivity *activity) {
        (void) activity;
    }

    void on_pause(ANativeActivity *activity) {
        (void) activity;
    }

    void on_stop(ANativeActivity *activity) {
        (void) activity;
    }

    void on_window_focus_changed(ANativeActivity *activity, int focused) {
        (void) activity;
        (void) focused;
    }

}  // namespace

extern "C" __attribute__((visibility("default")))
void native_activity_preload(JNIEnv *env, jobject activity) {
    if (!duckdetector::preload::has_early_detection_run()) {
        duckdetector::preload::run_early_detection();
    }
    if (!duckdetector::preload::virtualization::has_early_detection_run()) {
        duckdetector::preload::virtualization::run_early_detection();
    }
    start_launch_activity_and_finish(env, activity);
}

extern "C" __attribute__((visibility("default")))
void ANativeActivity_onCreate(ANativeActivity *activity, void *savedState, size_t savedStateSize) {
    (void) savedState;
    (void) savedStateSize;

    if (activity != nullptr && activity->callbacks != nullptr) {
        activity->callbacks->onDestroy = on_destroy;
        activity->callbacks->onStart = on_start;
        activity->callbacks->onResume = on_resume;
        activity->callbacks->onPause = on_pause;
        activity->callbacks->onStop = on_stop;
        activity->callbacks->onWindowFocusChanged = on_window_focus_changed;
    }

    if (!duckdetector::preload::has_early_detection_run()) {
        duckdetector::preload::run_early_detection();
    }
    if (!duckdetector::preload::virtualization::has_early_detection_run()) {
        duckdetector::preload::virtualization::run_early_detection();
    }

    JavaVM *vm = activity->vm;
    JNIEnv *env = nullptr;
    bool attached = false;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
            attached = true;
        }
    }

    if (env == nullptr) {
        LOGE("Failed to acquire JNIEnv for NativeActivity handoff");
        return;
    }

    start_launch_activity_and_finish(env, activity->clazz);
    if (attached) {
        vm->DetachCurrentThread();
    }
}
