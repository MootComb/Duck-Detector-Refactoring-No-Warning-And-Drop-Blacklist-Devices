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

    std::string trim(std::string value) {
        while (!value.empty() &&
               (value.back() == '\n' || value.back() == '\r' || value.back() == '\0' ||
                value.back() == ' ' || value.back() == '\t')) {
            value.pop_back();
        }
        while (!value.empty() &&
               (value.front() == ' ' || value.front() == '\t')) {
            value.erase(value.begin());
        }
        return value;
    }

    LoadedSelinuxSymbols load_selinux_symbols() {
        LoadedSelinuxSymbols symbols;
        symbols.is_selinux_enabled = resolve_symbol<IsSelinuxEnabledFn>(RTLD_DEFAULT,
                                                                        "is_selinux_enabled");
        symbols.security_getenforce = resolve_symbol<SecurityGetEnforceFn>(RTLD_DEFAULT,
                                                                           "security_getenforce");
        symbols.getcon = resolve_symbol<GetConFn>(RTLD_DEFAULT, "getcon");
        symbols.getpidcon = resolve_symbol<GetPidConFn>(RTLD_DEFAULT, "getpidcon");
        symbols.getfilecon = resolve_symbol<GetFileConFn>(RTLD_DEFAULT, "getfilecon");
        symbols.freecon = resolve_symbol<FreeConFn>(RTLD_DEFAULT, "freecon");
        symbols.check_access = resolve_symbol<SelinuxCheckAccessFn>(RTLD_DEFAULT,
                                                                    "selinux_check_access");
        symbols.set_callback = resolve_symbol<SelinuxSetCallbackFn>(RTLD_DEFAULT,
                                                                    "selinux_set_callback");
        symbols.get_callback = resolve_symbol<SelinuxGetCallbackFn>(RTLD_DEFAULT,
                                                                    "selinux_get_callback");

#ifdef RTLD_NOLOAD
        if (symbols.is_selinux_enabled == nullptr ||
            symbols.security_getenforce == nullptr ||
            symbols.getcon == nullptr ||
            symbols.getpidcon == nullptr ||
            symbols.getfilecon == nullptr ||
            symbols.freecon == nullptr ||
            symbols.check_access == nullptr ||
            symbols.set_callback == nullptr ||
            symbols.get_callback == nullptr) {
            symbols.handle = dlopen("libselinux.so", RTLD_NOW | RTLD_NOLOAD);
            if (symbols.handle != nullptr) {
                symbols.owns_handle = true;
                if (symbols.is_selinux_enabled == nullptr) {
                    symbols.is_selinux_enabled = resolve_symbol<IsSelinuxEnabledFn>(
                            symbols.handle,
                            "is_selinux_enabled"
                    );
                }
                if (symbols.security_getenforce == nullptr) {
                    symbols.security_getenforce = resolve_symbol<SecurityGetEnforceFn>(
                            symbols.handle,
                            "security_getenforce"
                    );
                }
                if (symbols.getcon == nullptr) {
                    symbols.getcon = resolve_symbol<GetConFn>(symbols.handle, "getcon");
                }
                if (symbols.getpidcon == nullptr) {
                    symbols.getpidcon = resolve_symbol<GetPidConFn>(symbols.handle, "getpidcon");
                }
                if (symbols.getfilecon == nullptr) {
                    symbols.getfilecon = resolve_symbol<GetFileConFn>(symbols.handle, "getfilecon");
                }
                if (symbols.freecon == nullptr) {
                    symbols.freecon = resolve_symbol<FreeConFn>(symbols.handle, "freecon");
                }
                if (symbols.check_access == nullptr) {
                    symbols.check_access = resolve_symbol<SelinuxCheckAccessFn>(
                            symbols.handle,
                            "selinux_check_access"
                    );
                }
                if (symbols.set_callback == nullptr) {
                    symbols.set_callback = resolve_symbol<SelinuxSetCallbackFn>(
                            symbols.handle,
                            "selinux_set_callback"
                    );
                }
                if (symbols.get_callback == nullptr) {
                    symbols.get_callback = resolve_symbol<SelinuxGetCallbackFn>(
                            symbols.handle,
                            "selinux_get_callback"
                    );
                }
            }
        }
#endif
        return symbols;
    }

    JavaSelinuxAccess resolve_java_selinux_access(JNIEnv *env) {
        JavaSelinuxAccess access;
        if (env == nullptr) {
            return access;
        }
        jclass local_class = env->FindClass("android/os/SELinux");
        if (local_class == nullptr) {
            env->ExceptionClear();
            return access;
        }
        access.selinux_class = reinterpret_cast<jclass>(env->NewGlobalRef(local_class));
        env->DeleteLocalRef(local_class);
        if (access.selinux_class == nullptr) {
            return access;
        }
        access.check_access = env->GetStaticMethodID(
                access.selinux_class,
                "checkSELinuxAccess",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z"
        );
        if (access.check_access == nullptr) {
            env->ExceptionClear();
            env->DeleteGlobalRef(access.selinux_class);
            access.selinux_class = nullptr;
            return access;
        }
        access.available = true;
        return access;
    }

    void release_java_selinux_access(
            JNIEnv *env,
            JavaSelinuxAccess &access
    ) {
        if (env != nullptr && access.selinux_class != nullptr) {
            env->DeleteGlobalRef(access.selinux_class);
        }
        access.selinux_class = nullptr;
        access.check_access = nullptr;
        access.available = false;
    }

    int dirty_policy_audit_callback(
            void *auditdata,
            security_class_t,
            char *msgbuf,
            size_t msgbufsize
    ) {
        const char *marker =
                auditdata != nullptr ? static_cast<const char *>(auditdata) : "dirty_policy";
        return std::snprintf(msgbuf, msgbufsize, "%s%s", kProbeMarkerPrefix, marker);
    }

    std::string make_dirty_policy_probe_marker() {
        return "dddirty_" + std::to_string(getpid()) + "_" +
               std::to_string(++g_dirty_policy_probe_counter);
    }

    std::optional<std::string> call_context_getter(
            const LoadedSelinuxSymbols &symbols,
            int (*getter)(char **)
    ) {
        if (getter == nullptr || symbols.freecon == nullptr) {
            return std::nullopt;
        }
        char *raw = nullptr;
        if (getter(&raw) != 0 || raw == nullptr) {
            if (raw != nullptr) {
                symbols.freecon(raw);
            }
            return std::nullopt;
        }
        std::string value = trim(raw);
        symbols.freecon(raw);
        return value;
    }

    std::optional<std::string> call_pid_context_getter(
            const LoadedSelinuxSymbols &symbols,
            pid_t pid
    ) {
        if (symbols.getpidcon == nullptr || symbols.freecon == nullptr) {
            return std::nullopt;
        }
        char *raw = nullptr;
        if (symbols.getpidcon(pid, &raw) != 0 || raw == nullptr) {
            if (raw != nullptr) {
                symbols.freecon(raw);
            }
            return std::nullopt;
        }
        std::string value = trim(raw);
        symbols.freecon(raw);
        return value;
    }

    std::optional<std::string> call_file_context_getter(
            const LoadedSelinuxSymbols &symbols,
            const char *path
    ) {
        if (symbols.getfilecon == nullptr || symbols.freecon == nullptr) {
            return std::nullopt;
        }
        char *raw = nullptr;
        if (symbols.getfilecon(path, &raw) != 0 || raw == nullptr) {
            if (raw != nullptr) {
                symbols.freecon(raw);
            }
            return std::nullopt;
        }
        std::string value = trim(raw);
        symbols.freecon(raw);
        return value;
    }

    std::string read_process_context() {
        std::ifstream input(kProcAttrCurrentPath);
        if (!input) {
            return {};
        }

        std::string context;
        std::getline(input, context, '\0');
        return trim(std::move(context));
    }

    std::string context_type(const std::string &context) {
        const std::size_t first = context.find(':');
        if (first == std::string::npos) {
            return {};
        }
        const std::size_t second = context.find(':', first + 1);
        if (second == std::string::npos) {
            return {};
        }
        const std::size_t third = context.find(':', second + 1);
        if (third == std::string::npos) {
            return context.substr(second + 1);
        }
        return context.substr(second + 1, third - second - 1);
    }

}  // namespace duckdetector::selinux::detail
