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

#include "selinux/context_validity_probe.h"
#include "selinux/context_validity_internal.h"
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <optional>
#include <string>
#include <sys/system_properties.h>
#include <utility>
#include <unistd.h>

namespace duckdetector::selinux::detail {

    void append_note(ContextValidityProbeSnapshot &snapshot, std::string note) {
        if (!note.empty()) {
            snapshot.notes.push_back(std::move(note));
        }
    }

    void append_boolean_note(
            ContextValidityProbeSnapshot &snapshot,
            const char *label,
            const std::optional<bool> &value
    ) {
        if (!value.has_value()) {
            append_note(snapshot, std::string(label) + "=unavailable");
            return;
        }
        append_note(snapshot, std::string(label) + (*value ? "=yes" : "=no"));
    }

    bool stable_result(
            const ContextCheckResult &first,
            const ContextCheckResult &second
    ) {
        return first.valid.has_value() == second.valid.has_value() &&
               (!first.valid.has_value() || *first.valid == *second.valid);
    }

    bool pair_matches_expected(
            const ControlPairResult &pair,
            const bool expected_valid
    ) {
        return pair.stable &&
               pair.first.valid.has_value() &&
               *pair.first.valid == expected_valid;
    }

    std::optional<bool> pair_valid_value(const ControlPairResult &pair) {
        if (!pair_matches_expected(pair, true) && !pair_matches_expected(pair, false)) {
            return std::nullopt;
        }
        return pair.first.valid;
    }

    std::optional<bool> pair_rejected_value(const ControlPairResult &pair) {
        if (!pair.stable || !pair.first.valid.has_value()) {
            return std::nullopt;
        }
        return !*pair.first.valid;
    }

    std::optional<bool> pair_allowed_value(const AccessPairResult &pair) {
        if (!pair.stable || !pair.first.has_value()) {
            return std::nullopt;
        }
        return pair.first;
    }

    ControlPairResult check_context_pair_validity(const char *context) {
        ControlPairResult result;
        result.first = check_context_validity(context);
        result.second = check_context_validity(context);
        result.stable = stable_result(result.first, result.second);
        return result;
    }

    std::optional<bool> check_access_rule(
            const LoadedSelinuxSymbols &symbols,
            const char *source,
            const char *target,
            const char *target_class,
            const char *permission,
            void *auditdata) {
        if (symbols.check_access != nullptr) {
            g_selinux_access_attempted.store(true, std::memory_order_relaxed);
            errno = 0;
            const int result = symbols.check_access(source, target, target_class, permission, auditdata);
            const int call_errno = errno;
            if (result == 0) {
                return true;
            }
            if (call_errno == EACCES || call_errno == EPERM) {
                return false;
            }
        }
        return std::nullopt;
    }

    std::optional<bool> check_java_access_rule(
            JNIEnv *env,
            const JavaSelinuxAccess &java_access,
            const char *source,
            const char *target,
            const char *target_class,
            const char *permission
    ) {
        if (!java_access.available || env == nullptr) {
            return std::nullopt;
        }
        jstring source_string = env->NewStringUTF(source);
        jstring target_string = env->NewStringUTF(target);
        jstring class_string = env->NewStringUTF(target_class);
        jstring permission_string = env->NewStringUTF(permission);
        if (source_string == nullptr || target_string == nullptr || class_string == nullptr ||
            permission_string == nullptr) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            if (source_string != nullptr) env->DeleteLocalRef(source_string);
            if (target_string != nullptr) env->DeleteLocalRef(target_string);
            if (class_string != nullptr) env->DeleteLocalRef(class_string);
            if (permission_string != nullptr) env->DeleteLocalRef(permission_string);
            return std::nullopt;
        }
        const jboolean result = env->CallStaticBooleanMethod(
                java_access.selinux_class,
                java_access.check_access,
                source_string,
                target_string,
                class_string,
                permission_string
        );
        const bool has_exception = env->ExceptionCheck();
        if (has_exception) {
            env->ExceptionClear();
        }
        env->DeleteLocalRef(source_string);
        env->DeleteLocalRef(target_string);
        env->DeleteLocalRef(class_string);
        env->DeleteLocalRef(permission_string);
        if (has_exception) {
            return std::nullopt;
        }
        return result == JNI_TRUE;
    }

    AccessPairResult check_access_rule_pair(
            const LoadedSelinuxSymbols &symbols,
            const char *source,
            const char *target,
            const char *target_class,
            const char *permission,
            void *auditdata) {
        AccessPairResult result;
        result.first = check_access_rule(symbols, source, target, target_class, permission, auditdata);
        result.second = check_access_rule(symbols, source, target, target_class, permission, auditdata);
        result.stable = result.first.has_value() == result.second.has_value() &&
                        (!result.first.has_value() || *result.first == *result.second);
        return result;
    }

    AccessPairResult check_java_access_rule_pair(
            JNIEnv *env,
            const JavaSelinuxAccess &java_access,
            const char *source,
            const char *target,
            const char *target_class,
            const char *permission
    ) {
        AccessPairResult result;
        result.first = check_java_access_rule(env, java_access, source, target, target_class, permission);
        result.second = check_java_access_rule(env, java_access, source, target, target_class, permission);
        result.stable = result.first.has_value() == result.second.has_value() &&
                        (!result.first.has_value() || *result.first == *result.second);
        return result;
    }

    void append_access_note(
            DirtyPolicyProbeSnapshot &snapshot,
            const char *label,
            const AccessPairResult &result
    ) {
        std::string line(label);
        line += '=';
        if (result.first.has_value()) {
            line += *result.first ? "allowed" : "denied";
        } else {
            line += "unavailable";
        }
        if (!result.stable) {
            line += " (unstable)";
        }
        snapshot.notes.push_back(std::move(line));
    }

    bool is_user_build() {
        char value[PROP_VALUE_MAX] = {};
        if (__system_property_get("ro.build.type", value) > 0) {
            return std::strcmp(value, "user") == 0;
        }
        return false;
    }

    void append_repeat_note(
            ContextValidityProbeSnapshot &snapshot,
            const char *label,
            const ContextCheckResult &result
    ) {
        std::string line(label);
        line += '=';
        if (result.valid.has_value()) {
            line += *result.valid ? "valid" : "invalid";
        } else {
            line += "unavailable";
        }
        if (!result.note.empty()) {
            line += " (";
            line += result.note;
            line += ')';
        }
        append_note(snapshot, std::move(line));
    }

    ContextCheckResult check_context_validity(const char *context) {
        ContextCheckResult result;

        int fd = open(kSelinuxContextPath, O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            const int error = errno;
            if (error == EINVAL) {
                result.valid = false;
                result.note = std::string("Invalid context: ") + context +
                              " errno=" + std::to_string(error);
            } else {
                result.note = std::string("Unavailable: ") + context +
                              " errno=" + std::to_string(error);
            }
            return result;
        }

        const ssize_t written = write(fd, context, std::strlen(context) + 1);
        const int error = errno;
        close(fd);

        if (written >= 0) {
            result.valid = true;
            return result;
        }

        if (error == EINVAL) {
            result.valid = false;
            result.note = std::string("Invalid context: ") + context +
                          " errno=" + std::to_string(error);
        } else {
            result.note = std::string("Unavailable: ") + context +
                          " errno=" + std::to_string(error);
        }
        return result;
    }

}  // namespace duckdetector::selinux::detail
