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

#include "selinuxpolicy/context_validity_probe.h"
#include "selinuxpolicy/context_validity_internal.h"
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

namespace duckdetector::selinux {

    using namespace detail;

    void close_process_local_avc() {
        // AOSP R: https://android.googlesource.com/platform/external/selinux/+/refs/heads/android11-release/libselinux/src/avc.c
        // avc_destroy() calls avc_netlink_close(); AOSP R：关闭 netlink FD，保留结果。
        if (!g_selinux_access_attempted.exchange(false, std::memory_order_relaxed)) {
            return;
        }

#ifdef RTLD_NOLOAD
        void *handle = dlopen("libselinux.so", RTLD_NOW | RTLD_NOLOAD);
        if (handle == nullptr) {
            return;
        }
        const auto destroy = reinterpret_cast<AvcDestroyFn>(dlsym(handle, "avc_destroy"));
        if (destroy != nullptr) {
            destroy();
        }
        dlclose(handle);
#endif
    }

    ContextValidityProbeSnapshot collect_context_validity_snapshot(JNIEnv *env) {
        ContextValidityProbeSnapshot snapshot;
        snapshot.query_method = kQueryMethod;
        const LoadedSelinuxSymbols symbols = load_selinux_symbols();
        JavaSelinuxAccess java_access = resolve_java_selinux_access(env);
        if (symbols.is_selinux_enabled != nullptr) {
            snapshot.selinux_enabled = symbols.is_selinux_enabled() == 1;
        }
        if (symbols.security_getenforce != nullptr) {
            const int enforce = symbols.security_getenforce();
            if (enforce == 0 || enforce == 1) {
                snapshot.selinux_enforced = enforce == 1;
            }
        }

        const std::string carrier_context = read_process_context();
        if (carrier_context.empty()) {
            snapshot.failure_reason = "Current process SELinux context unreadable.";
            release_java_selinux_access(env, java_access);
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }

        snapshot.available = true;
        snapshot.carrier_context = carrier_context;
        snapshot.carrier_matches_expected = context_type(carrier_context) == kExpectedCarrierType;
        append_note(snapshot, std::string("Carrier context: ") + carrier_context);
        append_note(snapshot, std::string("Expected carrier type: ") + kExpectedCarrierType);

        if (const auto current_context = call_context_getter(symbols, symbols.getcon);
            current_context.has_value()) {
            snapshot.pid_context_matches_current = (*current_context == carrier_context);
        }
        if (const auto pid_context = call_pid_context_getter(symbols, getpid());
            pid_context.has_value()) {
            snapshot.pid_context_matches_current = (*pid_context == carrier_context);
        }
        if (const auto proc_self_context = call_file_context_getter(symbols, "/proc/self");
            proc_self_context.has_value()) {
            snapshot.proc_self_context_matches_current = (*proc_self_context == carrier_context);
        }
        snapshot.dyntransition_check_passed = check_access_rule(
                symbols,
                kExpectedCarrierPrefix,
                kIsolatedAppContext,
                kProcessClass,
                kDyntransitionPermission
        );
        snapshot.dirty_policy = collect_dirty_policy_snapshot(
                symbols,
                env,
                java_access,
                carrier_context,
                snapshot.carrier_matches_expected,
                snapshot.dyntransition_check_passed
        );

        if (!snapshot.carrier_matches_expected ||
            carrier_context.rfind(kExpectedCarrierPrefix, 0) != 0) {
            snapshot.failure_reason = "Carrier context is not app_zygote.";
            append_note(snapshot, "The oracle is only meaningful from an app_zygote carrier.");
            release_java_selinux_access(env, java_access);
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }
        if (snapshot.selinux_enabled.has_value() && !*snapshot.selinux_enabled) {
            snapshot.failure_reason = "SELinux is disabled.";
            append_note(snapshot, "The carrier reported SELinux disabled.");
            release_java_selinux_access(env, java_access);
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }
        if (snapshot.selinux_enforced.has_value() && !*snapshot.selinux_enforced) {
            snapshot.failure_reason = "SELinux is permissive.";
            append_note(snapshot, "The carrier reported permissive SELinux.");
            release_java_selinux_access(env, java_access);
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }
        if (snapshot.pid_context_matches_current.has_value() &&
            !*snapshot.pid_context_matches_current) {
            snapshot.failure_reason = "PID context mismatch.";
            append_note(snapshot, "The carrier pid context did not match /proc/self/attr/current.");
            release_java_selinux_access(env, java_access);
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }
        if (snapshot.proc_self_context_matches_current.has_value() &&
            !*snapshot.proc_self_context_matches_current) {
            snapshot.failure_reason = "/proc/self context mismatch.";
            append_note(snapshot,
                        "The carrier /proc/self file context did not match /proc/self/attr/current.");
            release_java_selinux_access(env, java_access);
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }
        if (snapshot.dyntransition_check_passed.has_value() &&
            !*snapshot.dyntransition_check_passed) {
            snapshot.failure_reason = "app_zygote dyntransition self-check failed.";
            append_note(snapshot,
                        "The carrier could not confirm app_zygote -> isolated_app dyntransition.");
            release_java_selinux_access(env, java_access);
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }

        snapshot.probe_attempted = true;

        const ControlPairResult carrier_control = check_context_pair_validity(carrier_context.c_str());
        const ControlPairResult negative_control = check_context_pair_validity(kNegativeControlContext);
        const ControlPairResult file_control = check_context_pair_validity(kStockFileControlContext);
        const ControlPairResult negative_file_control =
                check_context_pair_validity(kNegativeFileControlContext);

        snapshot.carrier_control_valid = pair_valid_value(carrier_control);
        snapshot.negative_control_rejected = pair_rejected_value(negative_control);
        snapshot.file_control_valid = pair_valid_value(file_control);
        snapshot.file_negative_control_rejected = pair_rejected_value(negative_file_control);
        snapshot.oracle_controls_passed =
                pair_matches_expected(carrier_control, true) &&
                pair_matches_expected(negative_control, false) &&
                pair_matches_expected(file_control, true) &&
                pair_matches_expected(negative_file_control, false);

        append_note(snapshot, std::string("Query method: ") + kQueryMethod);
        append_note(snapshot, std::string("Positive control context: ") + carrier_context);
        append_note(snapshot, std::string("Negative control context: ") + kNegativeControlContext);
        append_note(snapshot, std::string("File control context: ") + kStockFileControlContext);
        append_note(snapshot,
                    std::string("File negative control context: ") + kNegativeFileControlContext);
        append_note(snapshot, carrier_control.first.note);
        append_note(snapshot, negative_control.first.note);
        append_note(snapshot, file_control.first.note);
        append_note(snapshot, negative_file_control.first.note);
        if (!carrier_control.stable) {
            append_note(snapshot, "Carrier control repeated inconsistently.");
        }
        if (!negative_control.stable) {
            append_note(snapshot, "Negative control repeated inconsistently.");
        }
        if (!file_control.stable) {
            append_note(snapshot, "File control repeated inconsistently.");
        }
        if (!negative_file_control.stable) {
            append_note(snapshot, "File negative control repeated inconsistently.");
        }
        append_boolean_note(snapshot, "Carrier control valid", snapshot.carrier_control_valid);
        append_boolean_note(snapshot, "Negative control rejected", snapshot.negative_control_rejected);
        append_boolean_note(snapshot, "File control valid", snapshot.file_control_valid);
        append_boolean_note(snapshot,
                            "File negative control rejected",
                            snapshot.file_negative_control_rejected);

        if (!snapshot.oracle_controls_passed) {
            snapshot.failure_reason = "Context validity oracle self-test failed.";
            append_note(snapshot,
                        "KSU-specific context queries were skipped to avoid interpreting an untrusted oracle.");
            release_java_selinux_access(env, java_access);
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }

        const ContextCheckResult domain_first = check_context_validity(kKsuContext);
        const ContextCheckResult domain_second = check_context_validity(kKsuContext);
        const ContextCheckResult file_first = check_context_validity(kKsuFileContext);
        const ContextCheckResult file_second = check_context_validity(kKsuFileContext);

        const bool domain_stable = stable_result(domain_first, domain_second);
        const bool file_stable = stable_result(file_first, file_second);
        snapshot.ksu_results_stable = domain_stable && file_stable;

        append_repeat_note(snapshot, "Domain repeat 1", domain_first);
        append_repeat_note(snapshot, "Domain repeat 2", domain_second);
        append_repeat_note(snapshot, "File repeat 1", file_first);
        append_repeat_note(snapshot, "File repeat 2", file_second);

        if (!snapshot.ksu_results_stable) {
            snapshot.failure_reason = "Context validity oracle repeatability failed.";
            append_note(snapshot,
                        "The KSU-specific context verdict changed across repeated writes, so it was not trusted.");
            release_java_selinux_access(env, java_access);
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }

        const ContextCheckResult domain_result = domain_first;
        const ContextCheckResult file_result = file_first;

        snapshot.ksu_domain_valid = domain_result.valid;
        snapshot.ksu_file_valid = file_result.valid;
        append_note(snapshot, domain_result.note);
        append_note(snapshot, file_result.note);

        if (domain_result.valid.has_value() && file_result.valid.has_value()) {
            snapshot.bit_pair.push_back(*domain_result.valid ? '1' : '0');
            snapshot.bit_pair.push_back(*file_result.valid ? '1' : '0');
            if (*domain_result.valid && *file_result.valid) {
                append_note(snapshot, "Both KSU-specific contexts were accepted by live policy.");
            } else if (!*domain_result.valid && !*file_result.valid) {
                append_note(snapshot, "Neither KSU-specific context was accepted by live policy.");
            } else {
                append_note(snapshot,
                            "Split verdict: one KSU-specific context was accepted while the other was not.");
            }
            release_java_selinux_access(env, java_access);
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }

        snapshot.failure_reason = "Context validity probe could not complete both checks.";
        if (!domain_result.valid.has_value() || !file_result.valid.has_value()) {
            append_note(snapshot,
                        "At least one KSU context write was unavailable from the current carrier.");
        }
        release_java_selinux_access(env, java_access);
        if (symbols.owns_handle && symbols.handle != nullptr) {
            dlclose(symbols.handle);
        }
        return snapshot;
    }

}  // namespace duckdetector::selinux
