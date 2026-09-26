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

#include "virtualization/snapshot_builder.h"
#include "virtualization/snapshot_scan.h"
#include "common/payload_codec.h"
#include "virtualization/egl_probe.h"

#include <sys/stat.h>
#include <sys/system_properties.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace duckdetector::virtualization {

    namespace {

        std::string read_property(const char *name) {
            char value[PROP_VALUE_MAX] = {0};
            if (__system_property_get(name, value) > 0) {
                return std::string(value);
            }
            return "";
        }

        bool file_exists(const char *path) {
            struct stat st{};
            return stat(path, &st) == 0;
        }

        std::string read_cmdline() {
            std::ifstream input("/proc/self/cmdline", std::ios::binary);
            if (!input.is_open()) {
                return "";
            }
            std::string data(
                    (std::istreambuf_iterator<char>(input)),
                    std::istreambuf_iterator<char>()
            );
            std::replace(data.begin(), data.end(), '\0', ' ');
            return data;
        }

        std::string encode_value(const std::string &value) {
            return common::escape_payload_value(value);
        }

    }  // namespace

    namespace snapshot_scan {

        bool contains_token(const std::string &text, const std::vector<std::string> &tokens) {
            for (const auto &token: tokens) {
                if (text.find(token) != std::string::npos) {
                    return true;
                }
            }
            return false;
        }

        void add_finding(
                Snapshot &snapshot,
                std::set<std::string> &dedupe,
                const SnapshotGroup group,
                const std::string &severity,
                const std::string &label,
                const std::string &value,
                const std::string &detail,
                const EarlySignal earlySignal
        ) {
            const std::string key =
                    std::string(group_name(group)) + "|" + severity + "|" + label + "|" + value + "|" +
                    detail;
            if (!dedupe.insert(key).second) {
                return;
            }
            snapshot.findings.push_back(SnapshotFinding{
                    group,
                    severity,
                    label,
                    value,
                    detail,
                    earlySignal,
            });
            if (severity == "WARNING" || severity == "DANGER") {
                switch (group) {
                    case SnapshotGroup::kEnvironment:
                        snapshot.environmentHitCount += 1;
                        break;
                    case SnapshotGroup::kTranslation:
                        snapshot.translationHitCount += 1;
                        break;
                    case SnapshotGroup::kRuntime:
                        snapshot.runtimeArtifactHitCount += 1;
                        break;
                }
            }
        }

    }  // namespace snapshot_scan

    namespace {

        using snapshot_scan::add_finding;
        using snapshot_scan::contains_token;
        using snapshot_scan::scan_fd_targets;
        using snapshot_scan::scan_maps;
        using snapshot_scan::scan_mount_namespace;
        using snapshot_scan::scan_mountinfo;

        std::string lowercase_copy(std::string value) {
            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
                return static_cast<char>(::tolower(ch));
            });
            return value;
        }

        void scan_properties(Snapshot &snapshot, std::set<std::string> &dedupe) {
            const std::string roKernelQemu = read_property("ro.kernel.qemu");
            if (roKernelQemu == "1") {
                add_finding(
                        snapshot,
                        dedupe,
                        SnapshotGroup::kEnvironment,
                        "DANGER",
                        "ro.kernel.qemu",
                        "Guest",
                        "ro.kernel.qemu=1 is a direct emulator guest property.",
                        EarlySignal::kQemuProperty
                );
            }

            const std::string roBootQemu = read_property("ro.boot.qemu");
            const std::string avdName = read_property("ro.boot.qemu.avd_name");
            const std::string qemuLcd = read_property("qemu.sf.lcd_density");
            if ((!roBootQemu.empty() && roBootQemu != "0") || !avdName.empty() ||
                !qemuLcd.empty()) {
                std::ostringstream detail;
                if (!roBootQemu.empty()) {
                    detail << "ro.boot.qemu=" << roBootQemu << "\n";
                }
                if (!avdName.empty()) {
                    detail << "ro.boot.qemu.avd_name=" << avdName << "\n";
                }
                if (!qemuLcd.empty()) {
                    detail << "qemu.sf.lcd_density=" << qemuLcd;
                }
                add_finding(
                        snapshot,
                        dedupe,
                        SnapshotGroup::kEnvironment,
                        "DANGER",
                        "QEMU guest properties",
                        "Present",
                        detail.str(),
                        EarlySignal::kQemuProperty
                );
            }

            const std::vector<std::pair<std::string, std::string>> hardware_props = {
                    {"ro.hardware",       read_property("ro.hardware")},
                    {"ro.boot.hardware",  read_property("ro.boot.hardware")},
                    {"ro.product.board",  read_property("ro.product.board")},
                    {"ro.board.platform", read_property("ro.board.platform")},
            };
            std::ostringstream hardware_detail;
            bool has_hardware_cluster = false;
            for (const auto &entry: hardware_props) {
                if (entry.second.find("goldfish") != std::string::npos ||
                    entry.second.find("ranchu") != std::string::npos) {
                    has_hardware_cluster = true;
                    hardware_detail << entry.first << "=" << entry.second << "\n";
                }
            }
            if (has_hardware_cluster) {
                add_finding(
                        snapshot,
                        dedupe,
                        SnapshotGroup::kEnvironment,
                        "DANGER",
                        "Emulator hardware props",
                        "goldfish/ranchu",
                        hardware_detail.str(),
                        EarlySignal::kEmulatorHardware
                );
            }

            const std::string nativeBridge = read_property("ro.dalvik.vm.native.bridge");
            if (!nativeBridge.empty() && nativeBridge != "0") {
                add_finding(
                        snapshot,
                        dedupe,
                        SnapshotGroup::kTranslation,
                        "WARNING",
                        "ro.dalvik.vm.native.bridge",
                        nativeBridge,
                        "ART native bridge is configured for translated execution."
                );
            }

            const std::string hypervisorSupported = read_property(
                    "ro.boot.hypervisor.vm.supported");
            if (!hypervisorSupported.empty() && hypervisorSupported != "0") {
                add_finding(
                        snapshot,
                        dedupe,
                        SnapshotGroup::kEnvironment,
                        "INFO",
                        "Hypervisor capability",
                        hypervisorSupported,
                        "Capability-only signal. It does not imply the current process is inside a guest."
                );
            }
        }

        void scan_device_nodes(Snapshot &snapshot, std::set<std::string> &dedupe) {
            const std::vector<const char *> nodes = {
                    "/dev/qemu_pipe",
                    "/dev/qemu_trace",
                    "/dev/goldfish_pipe",
                    "/dev/socket/qemud",
            };
            for (const auto *node: nodes) {
                if (file_exists(node)) {
                    add_finding(
                            snapshot,
                            dedupe,
                            SnapshotGroup::kRuntime,
                            "DANGER",
                            "Emulator device node",
                            node,
                            std::string("Current app context can see emulator device node: ") + node,
                            EarlySignal::kEmulatorDeviceNode
                    );
                }
            }
        }

        void scan_cmdline(Snapshot &snapshot, std::set<std::string> &dedupe) {
            const std::string cmdline = read_cmdline();
            if (cmdline.find("-Xnative-bridge") != std::string::npos) {
                add_finding(
                        snapshot,
                        dedupe,
                        SnapshotGroup::kTranslation,
                        "WARNING",
                        "Cmdline native bridge",
                        "Present",
                        cmdline
                );
            }
        }

        void scan_renderer(Snapshot &snapshot, std::set<std::string> &dedupe) {
            const auto renderer = collect_renderer_snapshot();
            snapshot.eglAvailable = renderer.available;
            snapshot.eglVendor = renderer.vendor;
            snapshot.eglRenderer = renderer.renderer;
            snapshot.eglVersion = renderer.version;
            if (!renderer.available) {
                return;
            }
            const std::string lowered = lowercase_copy(
                    renderer.renderer + " " + renderer.vendor + " " + renderer.version
            );
            if (contains_token(lowered,
                               {"android emulator opengl es translator", "gfxstream", "virgl",
                                "virtio_gpu", "crosvm"})) {
                add_finding(
                        snapshot,
                        dedupe,
                        SnapshotGroup::kRuntime,
                        "WARNING",
                        "Graphics renderer",
                        renderer.renderer.empty() ? "Detected" : renderer.renderer,
                        renderer.vendor + "\n" + renderer.renderer + "\n" + renderer.version
                );
            } else if (contains_token(lowered, {"swiftshader"})) {
                add_finding(
                        snapshot,
                        dedupe,
                        SnapshotGroup::kRuntime,
                        "INFO",
                        "Graphics renderer",
                        renderer.renderer.empty() ? "SwiftShader" : renderer.renderer,
                        renderer.vendor + "\n" + renderer.renderer + "\n" + renderer.version
                );
            }
        }

    }  // namespace

    Snapshot collect_snapshot(const SnapshotOptions &options) {
        Snapshot snapshot;
        snapshot.available = true;
        std::set<std::string> dedupe;

        scan_mount_namespace(snapshot);
        scan_properties(snapshot, dedupe);
        scan_device_nodes(snapshot, dedupe);
        scan_maps(snapshot, dedupe);
        scan_mountinfo(snapshot, dedupe);
        scan_fd_targets(snapshot, dedupe);
        scan_cmdline(snapshot, dedupe);
        if (options.probeRenderer) {
            scan_renderer(snapshot, dedupe);
        }

        return snapshot;
    }

    std::string encode_snapshot(const Snapshot &snapshot) {
        std::ostringstream output;
        output << "AVAILABLE=" << (snapshot.available ? 1 : 0) << '\n';
        output << "EGL_AVAILABLE=" << (snapshot.eglAvailable ? 1 : 0) << '\n';
        output << "EGL_VENDOR=" << encode_value(snapshot.eglVendor) << '\n';
        output << "EGL_RENDERER=" << encode_value(snapshot.eglRenderer) << '\n';
        output << "EGL_VERSION=" << encode_value(snapshot.eglVersion) << '\n';
        output << "MOUNT_NAMESPACE_INODE=" << encode_value(snapshot.mountNamespaceInode) << '\n';
        output << "APEX_MOUNT_KEY=" << encode_value(snapshot.apexMountKey) << '\n';
        output << "SYSTEM_MOUNT_KEY=" << encode_value(snapshot.systemMountKey) << '\n';
        output << "VENDOR_MOUNT_KEY=" << encode_value(snapshot.vendorMountKey) << '\n';
        output << "MAP_LINE_COUNT=" << snapshot.mapLineCount << '\n';
        output << "FD_COUNT=" << snapshot.fdCount << '\n';
        output << "MOUNTINFO_LINE_COUNT=" << snapshot.mountInfoCount << '\n';
        output << "ENVIRONMENT_HITS=" << snapshot.environmentHitCount << '\n';
        output << "TRANSLATION_HITS=" << snapshot.translationHitCount << '\n';
        output << "RUNTIME_HITS=" << snapshot.runtimeArtifactHitCount << '\n';
        for (const auto &finding: snapshot.findings) {
            // The value column carries device text - a property value, an emulator device node, a
            // mapped library path, a mount point, a driver renderer string - and a path may legally
            // contain a tab or a newline. Escaping only the last column let such a value shift the
            // columns after it, or end the record and turn its remainder into bogus keys.
            output << "FINDING="
                   << encode_value(group_name(finding.group)) << '\t'
                   << encode_value(finding.severity) << '\t'
                   << encode_value(finding.label) << '\t'
                   << encode_value(finding.value) << '\t'
                   << encode_value(finding.detail) << '\n';
        }
        return output.str();
    }

}  // namespace duckdetector::virtualization
