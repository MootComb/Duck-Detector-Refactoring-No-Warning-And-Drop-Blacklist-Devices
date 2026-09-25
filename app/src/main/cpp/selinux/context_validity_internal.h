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

#include "selinux/context_validity_probe.h"
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

    constexpr int kSelinuxCbAudit = 1;

    constexpr const char *kProcAttrCurrentPath = "/proc/self/attr/current";

    constexpr const char *kSelinuxContextPath = "/sys/fs/selinux/context";

    constexpr const char *kExpectedCarrierType = "app_zygote";

    constexpr const char *kExpectedCarrierPrefix = "u:r:app_zygote:s0";

    constexpr const char *kIsolatedAppContext = "u:r:isolated_app:s0";

    constexpr const char *kKsuContext = "u:r:ksu:s0";

    constexpr const char *kKsuFileContext = "u:object_r:ksu_file:s0";

    constexpr const char *kNegativeControlContext = "u:r:duckdetector_context_oracle_sentinel:s0";

    constexpr const char *kStockFileControlContext = "u:object_r:system_data_file:s0";

    constexpr const char *kNegativeFileControlContext =
            "u:object_r:duckdetector_context_oracle_sentinel_file:s0";

    constexpr const char *kQueryMethod = "raw selinuxfs write";

    constexpr const char *kDirtyPolicyQueryMethod = "selinux_check_access";

    constexpr const char *kProbeMarkerPrefix = "duckdetector_probe=";

    constexpr const char *kProcessClass = "process";

    constexpr const char *kDyntransitionPermission = "dyntransition";

    constexpr const char *kCapabilityClass = "capability";

    constexpr const char *kBinderClass = "binder";

    constexpr const char *kUnixStreamSocketClass = "unix_stream_socket";

    constexpr const char *kFileClass = "file";

    constexpr const char *kDirClass = "dir";

    constexpr const char *kReadPermission = "read";

    constexpr const char *kCallPermission = "call";

    constexpr const char *kConnectToPermission = "connectto";

    constexpr const char *kExecmemPermission = "execmem";

    constexpr const char *kTransitionPermission = "transition";

    constexpr const char *kSearchPermission = "search";

    constexpr const char *kSysAdminPermission = "sys_admin";

    constexpr const char *kWritePermission = "write";

    constexpr const char *kSystemServerContext = "u:r:system_server:s0";

    constexpr const char *kFsckUntrustedContext = "u:r:fsck_untrusted:s0";

    constexpr const char *kShellContext = "u:r:shell:s0";

    constexpr const char *kSuContext = "u:r:su:s0";

    constexpr const char *kAdbdContext = "u:r:adbd:s0";

    constexpr const char *kAdbrootContext = "u:r:adbroot:s0";

    constexpr const char *kUntrustedAppContext = "u:r:untrusted_app:s0";

    constexpr const char *kMagiskContext = "u:r:magisk:s0";

    constexpr const char *kDroidspacesdContext = "u:r:droidspacesd:s0";

    constexpr const char *kLsposedFileContext = "u:object_r:lsposed_file:s0";

    constexpr const char *kMsdAppContext = "u:r:msd_app:s0";

    constexpr const char *kMsdDaemonContext = "u:r:msd_daemon:s0";

    constexpr const char *kSelinuxfsContext = "u:object_r:selinuxfs:s0";

    constexpr const char *kConfigfsContext = "u:object_r:configfs:s0";

    constexpr const char *kXposedDataContext = "u:object_r:xposed_data:s0";

    constexpr const char *kZygoteContext = "u:r:zygote:s0";

    constexpr const char *kAdbDataFileContext = "u:object_r:adb_data_file:s0";

    constexpr const char *kDirtyPolicyNegativeControlContext =
            "u:r:duckdetector_dirty_policy_sentinel:s0";

    using security_class_t = unsigned short;

    union selinux_callback {
        int (*func_log)(int type, const char *fmt, ...);

        int
        (*func_audit)(void *auditdata, security_class_t cls, char *msgbuf, size_t msgbufsize);

        void *raw;
    };

    using IsSelinuxEnabledFn = int (*)();

    using SecurityGetEnforceFn = int (*)();

    using GetConFn = int (*)(char **);

    using GetPidConFn = int (*)(pid_t, char **);

    using GetFileConFn = int (*)(const char *, char **);

    using FreeConFn = void (*)(char *);

    using SelinuxCheckAccessFn = int (*)(
            const char *scon,
            const char *tcon,
            const char *tclass,
            const char *perm,
            void *auditdata
    );

    using SelinuxSetCallbackFn = void (*)(int type, selinux_callback callback);

    using SelinuxGetCallbackFn = selinux_callback (*)(int type);

    struct LoadedSelinuxSymbols {
        void *handle = nullptr;
        bool owns_handle = false;
        IsSelinuxEnabledFn is_selinux_enabled = nullptr;
        SecurityGetEnforceFn security_getenforce = nullptr;
        GetConFn getcon = nullptr;
        GetPidConFn getpidcon = nullptr;
        GetFileConFn getfilecon = nullptr;
        FreeConFn freecon = nullptr;
        SelinuxCheckAccessFn check_access = nullptr;
        SelinuxSetCallbackFn set_callback = nullptr;
        SelinuxGetCallbackFn get_callback = nullptr;
    };

    struct ContextCheckResult {
        std::optional<bool> valid;
        std::string note;
    };

    struct ControlPairResult {
        ContextCheckResult first;
        ContextCheckResult second;
        bool stable = false;
    };

    struct AccessPairResult {
        std::optional<bool> first;
        std::optional<bool> second;
        bool stable = false;
    };

    struct JavaSelinuxAccess {
        jclass selinux_class = nullptr;
        jmethodID check_access = nullptr;
        bool available = false;
    };

    inline std::atomic<unsigned int> g_dirty_policy_probe_counter{0};

    inline std::atomic<bool> g_selinux_access_attempted{false};

    using AvcDestroyFn = void (*)();

    std::string trim(std::string value);

    template<typename T>
    T resolve_symbol(
            void *handle,
            const char *symbol
    ) {
        return reinterpret_cast<T>(dlsym(handle, symbol));
    }

    LoadedSelinuxSymbols load_selinux_symbols();

    JavaSelinuxAccess resolve_java_selinux_access(JNIEnv *env);

    void release_java_selinux_access(
            JNIEnv *env,
            JavaSelinuxAccess &access
    );

    int dirty_policy_audit_callback(
            void *auditdata,
            security_class_t,
            char *msgbuf,
            size_t msgbufsize
    );

    std::string make_dirty_policy_probe_marker();

    class ScopedDirtyPolicyAuditMarker {
    public:
        explicit ScopedDirtyPolicyAuditMarker(const LoadedSelinuxSymbols &symbols)
                : symbols_(symbols) {
            if (symbols_.set_callback == nullptr || symbols_.get_callback == nullptr) {
                return;
            }

            previous_callback_ = symbols_.get_callback(kSelinuxCbAudit);
            selinux_callback callback{};
            callback.func_audit = dirty_policy_audit_callback;
            marker_ = make_dirty_policy_probe_marker();
            symbols_.set_callback(kSelinuxCbAudit, callback);
            installed_ = true;
        }

        ~ScopedDirtyPolicyAuditMarker() {
            if (installed_ && symbols_.set_callback != nullptr) {
                symbols_.set_callback(kSelinuxCbAudit, previous_callback_);
            }
        }

        ScopedDirtyPolicyAuditMarker(const ScopedDirtyPolicyAuditMarker &) = delete;
        ScopedDirtyPolicyAuditMarker &operator=(const ScopedDirtyPolicyAuditMarker &) = delete;

        bool installed() const {
            return installed_;
        }

        const std::string &marker() const {
            return marker_;
        }

        void *auditdata() {
            return installed_ ? marker_.data() : nullptr;
        }

    private:
        const LoadedSelinuxSymbols &symbols_;
        selinux_callback previous_callback_{};
        bool installed_ = false;
        std::string marker_;
    };

    std::optional<std::string> call_context_getter(
            const LoadedSelinuxSymbols &symbols,
            int (*getter)(char **)
    );

    std::optional<std::string> call_pid_context_getter(
            const LoadedSelinuxSymbols &symbols,
            pid_t pid
    );

    std::optional<std::string> call_file_context_getter(
            const LoadedSelinuxSymbols &symbols,
            const char *path
    );

    std::string read_process_context();

    std::string context_type(const std::string &context);

    void append_note(ContextValidityProbeSnapshot &snapshot, std::string note);

    void append_boolean_note(
            ContextValidityProbeSnapshot &snapshot,
            const char *label,
            const std::optional<bool> &value
    );

    bool stable_result(
            const ContextCheckResult &first,
            const ContextCheckResult &second
    );

    bool pair_matches_expected(
            const ControlPairResult &pair,
            const bool expected_valid
    );

    std::optional<bool> pair_valid_value(const ControlPairResult &pair);

    std::optional<bool> pair_rejected_value(const ControlPairResult &pair);

    std::optional<bool> pair_allowed_value(const AccessPairResult &pair);

    ControlPairResult check_context_pair_validity(const char *context);

    std::optional<bool> check_access_rule(
            const LoadedSelinuxSymbols &symbols,
            const char *source,
            const char *target,
            const char *target_class,
            const char *permission,
            void *auditdata = nullptr
    );

    std::optional<bool> check_java_access_rule(
            JNIEnv *env,
            const JavaSelinuxAccess &java_access,
            const char *source,
            const char *target,
            const char *target_class,
            const char *permission
    );

    AccessPairResult check_access_rule_pair(
            const LoadedSelinuxSymbols &symbols,
            const char *source,
            const char *target,
            const char *target_class,
            const char *permission,
            void *auditdata = nullptr
    );

    AccessPairResult check_java_access_rule_pair(
            JNIEnv *env,
            const JavaSelinuxAccess &java_access,
            const char *source,
            const char *target,
            const char *target_class,
            const char *permission
    );

    void append_access_note(
            DirtyPolicyProbeSnapshot &snapshot,
            const char *label,
            const AccessPairResult &result
    );

    bool is_user_build();

    DirtyPolicyProbeSnapshot collect_dirty_policy_snapshot(
            const LoadedSelinuxSymbols &symbols,
            JNIEnv *env,
            const JavaSelinuxAccess &java_access,
            const std::string &carrier_context,
            const bool carrier_matches_expected,
            const std::optional<bool> &dyntransition_check_passed
    );

    void append_repeat_note(
            ContextValidityProbeSnapshot &snapshot,
            const char *label,
            const ContextCheckResult &result
    );

    ContextCheckResult check_context_validity(const char *context);

}  // namespace duckdetector::selinux::detail
