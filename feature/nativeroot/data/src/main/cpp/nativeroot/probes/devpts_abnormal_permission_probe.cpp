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

#include "nativeroot/probes/devpts_abnormal_permission_probe.h"

#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

namespace duckdetector::nativeroot {

    namespace {

        void append_line(std::string &target, const std::string &line) {
            target += line;
            target += '\n';
        }

        void note_error(
                ProbeResult &result,
                const char *path,
                const char *step,
                const int error
        ) {
            result.denied_count++;
            append_line(result.extra_text, std::string("Test: ") + path);
            append_line(result.extra_text, std::string(step) + " errno=" + std::to_string(error));
            result.extra_text += '\n';
        }

        void inspect_pty_path(
                const char *path,
                ProbeResult &result,
                const bool required_sample
        ) {
            struct stat st{};
            if (lstat(path, &st) == -1) {
                if (required_sample) {
                    note_error(result, path, "lstat failed", errno);
                }
                return;
            }

            result.checked_count++;
            char attr_val[256] = {0};
            bool is_abnormal = false;

            Finding finding;
            finding.group = "PATH";
            finding.label = path;
            finding.severity = Severity::kWarning;

            append_line(finding.detail, std::string("Test: ") + path);
            append_line(finding.detail, std::string("Owner: ") + std::to_string(st.st_uid));

            if (st.st_uid == 0) {
                result.flags.root = true;
                is_abnormal = true;
                append_line(finding.detail, "Found ROOT PTY");
            }

            const ssize_t len = getxattr(path, "security.selinux", attr_val, sizeof(attr_val) - 1);
            if (len >= 0) {
                attr_val[len] = '\0';
                append_line(
                        finding.detail,
                        std::string("SELinux: ") + (len > 0 ? attr_val : "<empty>")
                );

                if (strstr(attr_val, "ksu_file") != nullptr) {
                    result.flags.root = true;
                    result.flags.kernel_su = true;
                    is_abnormal = true;
                    append_line(finding.detail, "Found KernelSU file Domain");
                }
            } else {
                const int error = errno;
                result.denied_count++;
                append_line(
                        finding.detail,
                        std::string("SELinux: unavailable errno=") + std::to_string(error)
                );
            }

            if (is_abnormal) {
                finding.value = "Abnormal Permission Detected";
                finding.severity = Severity::kDanger;
                result.findings.push_back(finding);
                result.hit_count++;
            }

            result.extra_text += finding.detail;
            result.extra_text += '\n';
        }

    }  // namespace

    ProbeResult run_devpts_permission_check() {
        ProbeResult result;
        result.extra_text = "";

        // We cannot enumerate every PTY on Android, so sample the low range plus one fresh PTY.
        char path_buf[32];
        for (int i = 0; i <= 100; ++i) {
            snprintf(path_buf, sizeof(path_buf), "/dev/pts/%d", i);
            inspect_pty_path(path_buf, result, false);
        }

        // KernelSU devpts hooks can stamp the newly allocated PTY as u:object_r:ksu_file:s0.
        // Mostly, this path is useless
        // Unless KernelSU Forks remove ksu_is_allow_uid check
        // But them even reintroduce devpts hook, no one can guarantee they won't do that.
        // Just in case to try detect
        const int master_fd = posix_openpt(O_RDWR | O_NOCTTY);
        if (master_fd == -1) {
            note_error(result, "/dev/pts/new", "posix_openpt failed", errno);
            return result;
        }

        if (grantpt(master_fd) != 0) {
            note_error(result, "/dev/pts/new", "grantpt failed", errno);
            close(master_fd);
            return result;
        }

        if (unlockpt(master_fd) != 0) {
            note_error(result, "/dev/pts/new", "unlockpt failed", errno);
            close(master_fd);
            return result;
        }

        char *pts_name = ptsname(master_fd);
        if (pts_name != nullptr) {
            inspect_pty_path(pts_name, result, true);
        } else {
            note_error(result, "/dev/pts/new", "ptsname failed", errno);
        }

        close(master_fd);
        return result;
    }

}  // namespace duckdetector::nativeroot
