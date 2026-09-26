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

#include <jni.h>

#include <cctype>
#include <array>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <vector>

#include "customrom/property_integrity_probe.h"
#include "customrom/symbol_probe.h"

namespace {

    struct Finding {
        const char *label;
        const char *path;
    };

    constexpr Finding kPlatformFiles[] = {
            {"LineageOS",       "/system/framework/org.lineageos.platform-res.apk"},
            {"LineageOS",       "/system/framework/oat/arm64/org.lineageos.platform.vdex"},
            {"LineageOS",       "/system/framework/oat/arm64/org.lineageos.platform.odex"},
            {"LineageOS",       "/system/framework/oat/arm/org.lineageos.platform.vdex"},
            {"LineageOS",       "/system/framework/oat/arm/org.lineageos.platform.odex"},
            {"LineageOS",       "/system_ext/framework/org.lineageos.platform.jar"},
            {"crDroid",         "/system/framework/crdroid-res.apk"},
            {"PixelExperience", "/system/framework/org.pixelexperience.platform-res.apk"},
            {"Evolution-X",     "/system/framework/org.evolution.framework-res.apk"},
            {"ParanoidAndroid", "/system/framework/co.aospa.framework-res.apk"},
            {"ProtonAOSP",      "/system/framework/org.protonaosp.framework-res.apk"},
            {"OmniROM",         "/system/framework/org.omnirom.platform-res.apk"},
            {"LineageOS",       "/product/framework/org.lineageos.platform-res.apk"},
            {"LineageOS",       "/product/overlay/LineageSettingsProvider.apk"},
    };

    constexpr Finding kPolicyKeywords[] = {
            {"LineageOS",       "hal_lineage"},
            {"LineageOS",       ".lineage"},
            {"ParanoidAndroid",  "hal_aospa"},
            {"ParanoidAndroid",  ".aospa"},
    };

    constexpr Finding kOverlayPatterns[] = {
            {"LineageOS",       "lineage"},
            {"crDroid",         "crdroid"},
            {"ParanoidAndroid", "aospa"},
            {"PixelExperience", "pixelexperience"},
            {"Evolution-X",     "evolution"},
            {"OmniROM",         "omnirom"},
            {"ProtonAOSP",      "protonaosp"},
    };

    constexpr const char *kRecoveryScriptPaths[] = {
            "/system/addon.d",
            "/system/bin/install-recovery.sh",
            "/system/etc/install-recovery.sh",
            "/vendor/bin/install-recovery.sh",
    };

    constexpr const char *kPolicyFiles[] = {
            "/vendor/etc/selinux/vendor_sepolicy.cil",
            "/system_ext/etc/selinux/system_ext_sepolicy.cil",
            "/vendor/etc/selinux/vendor_file_contexts",
    };

    constexpr const char *kOverlayDirs[] = {
            "/product/overlay",
            "/vendor/overlay",
            "/system/overlay",
            "/system_ext/overlay",
    };

    bool path_exists(const char *path) {
        struct stat st{};
        return stat(path, &st) == 0;
    }

    bool read_file(const char *path, std::string &content) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            return false;
        }

        content.clear();
        char buffer[4096];
        ssize_t bytes_read = 0;
        while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
            content.append(buffer, static_cast<size_t>(bytes_read));
        }
        close(fd);
        return bytes_read >= 0;
    }

    std::vector<std::string> list_dir(const char *path) {
        std::vector<std::string> files;
        DIR *dir = opendir(path);
        if (dir == nullptr) {
            return files;
        }

        dirent *entry = nullptr;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_name[0] == '.') {
                continue;
            }
            files.emplace_back(entry->d_name);
        }
        closedir(dir);
        return files;
    }

    std::string lowercase_copy(std::string value) {
        for (char &ch: value) {
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
        return value;
    }

    int count_keyword(const std::string &content, const char *keyword) {
        int count = 0;
        const std::string lower_content = lowercase_copy(content);
        const std::string lower_keyword = lowercase_copy(keyword);
        size_t index = 0;
        while (true) {
            index = lower_content.find(lower_keyword, index);
            if (index == std::string::npos) {
                break;
            }
            ++count;
            index += lower_keyword.size();
        }
        return count;
    }

    std::vector<std::string> parse_map_injection() {
        std::vector<std::string> findings;
        std::string content;
        if (!read_file("/proc/self/maps", content)) {
            return findings;
        }

        struct MappingInfo {
            int count = 0;
            std::set<std::string> paths;
        };

        std::map<std::string, MappingInfo> device_mappings;
        std::istringstream stream(content);
        std::string line;

        while (std::getline(stream, line)) {
            if (line.find("framework-res.apk") == std::string::npos) {
                continue;
            }

            const size_t dev_pos = line.find(':');
            if (dev_pos == std::string::npos || dev_pos < 2) {
                continue;
            }

            const size_t dev_start_pos = line.rfind(' ', dev_pos - 2);
            if (dev_start_pos == std::string::npos) {
                continue;
            }

            const size_t dev_end_pos = line.find(' ', dev_pos);
            if (dev_end_pos == std::string::npos) {
                continue;
            }

            const std::string device_id = line.substr(dev_start_pos + 1,
                                                      dev_end_pos - dev_start_pos - 1);
            const size_t path_start = line.rfind('/');
            const std::string path = path_start != std::string::npos ? line.substr(path_start) : "";

            device_mappings[device_id].count++;
            if (!path.empty()) {
                device_mappings[device_id].paths.insert(path);
            }
        }

        bool has_custom_rom_path = false;
        for (const auto &[device_id, info]: device_mappings) {
            (void) device_id;
            for (const auto &path: info.paths) {
                const std::string lower_path = lowercase_copy(path);
                if (lower_path.find("lineage") != std::string::npos ||
                    lower_path.find("crdroid") != std::string::npos ||
                    lower_path.find("aospa") != std::string::npos ||
                    lower_path.find("evolution") != std::string::npos ||
                    lower_path.find("pixelexperience") != std::string::npos ||
                    lower_path.find("omnirom") != std::string::npos ||
                    lower_path.find("protonaosp") != std::string::npos) {
                    has_custom_rom_path = true;
                    break;
                }
            }
            if (has_custom_rom_path) {
                break;
            }
        }

        if (device_mappings.size() >= 3 || has_custom_rom_path) {
            findings.emplace_back(
                    "framework-res.apk mapped from " + std::to_string(device_mappings.size()) +
                    " devices (possible overlay injection)"
            );
            for (const auto &[device_id, info]: device_mappings) {
                findings.emplace_back(
                        "Device " + device_id + ": " + std::to_string(info.count) + " mappings"
                );
            }
        }

        return findings;
    }

    jstring to_jstring(JNIEnv *env, const std::string &value) {
        return env->NewStringUTF(value.c_str());
    }

    std::string escape_line(const std::string &value) {
        std::string escaped;
        escaped.reserve(value.size());
        for (const char ch: value) {
            switch (ch) {
                case '\n':
                    escaped += "\\n";
                    break;
                case '\r':
                    escaped += "\\r";
                    break;
                case '|':
                    escaped += "\\u007c";
                    break;
                default:
                    escaped += ch;
                    break;
            }
        }
        return escaped;
    }

    int android_sdk_level() {
        std::array<char, PROP_VALUE_MAX> value{};
        if (__system_property_get("ro.build.version.sdk", value.data()) <= 0) {
            return 0;
        }
        return std::atoi(value.data());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_customrom_data_native_CustomRomNativeBridge_nativeCollectSnapshot(
        JNIEnv *env,
        jobject
) {
    std::ostringstream output;
    output << "AVAILABLE=1\n";

    const auto property_integrity = customrom::scan_property_integrity();
    output << "PROPAREA_AVAILABLE=" << (property_integrity.available ? 1 : 0) << "\n";
    output << "PROPAREA_CONTEXTS=" << property_integrity.context_count << "\n";
    output << "PROPAREA_AREA_ANOMALIES=" << property_integrity.area_anomaly_count << "\n";
    output << "PROPAREA_ITEM_ANOMALIES=" << property_integrity.item_anomaly_count << "\n";

    const auto map_injection_lines = parse_map_injection();
    if (!map_injection_lines.empty()) {
        std::ostringstream detail;
        for (size_t index = 0; index < map_injection_lines.size(); ++index) {
            if (index > 0) {
                detail << "\\n";
            }
            detail << map_injection_lines[index];
        }
        output << "MAP=Modified System|framework-res.apk|" << detail.str() << "\n";
    }

    for (const auto &finding: property_integrity.findings) {
        output << "MODIFICATION=" << escape_line(finding.category) << "|"
               << escape_line(finding.signal) << "|"
               << escape_line(finding.summary) << "|"
               << escape_line(finding.detail) << "\n";
    }

    for (const auto &finding: kPlatformFiles) {
        if (path_exists(finding.path)) {
            output << "PLATFORM=" << finding.label << "|" << finding.path << "\n";
        }
    }

    for (const char *path: kRecoveryScriptPaths) {
        if (path_exists(path)) {
            output << "SCRIPT=" << path << "\n";
        }
    }

    for (const char *policy_file: kPolicyFiles) {
        std::string content;
        if (!read_file(policy_file, content)) {
            continue;
        }

        for (const auto &keyword: kPolicyKeywords) {
            const int count = count_keyword(content, keyword.path);
            if (count > 0) {
                output << "POLICY=" << keyword.label << "|" << policy_file << "|" << keyword.path
                       << "|" << count << "\n";
            }
        }
    }

    for (const char *overlay_dir: kOverlayDirs) {
        for (const auto &entry: list_dir(overlay_dir)) {
            const std::string lower_entry = lowercase_copy(entry);
            for (const auto &pattern: kOverlayPatterns) {
                if (lower_entry.find(pattern.path) != std::string::npos) {
                    output << "OVERLAY=" << pattern.label << "|" << overlay_dir << "/" << entry
                           << "\n";
                    break;
                }
            }
        }
    }

    constexpr const char *kSymbolStagefright = "_ZN7android15ANetworkSession10threadLoopEv";
    const bool symbol_scan_available = android_sdk_level() >= 29;
    output << "SYMBOL_AVAILABLE=" << (symbol_scan_available ? 1 : 0) << "\n";
    if (symbol_scan_available) {
        for (const auto &path: customrom::find_loaded_symbol_paths("libstagefright.so",
                                                                   kSymbolStagefright)) {
            output << "SYMBOL=Native symbol trace|ANetworkSession::threadLoopEv|" << path
                   << "\n";
        }
    }

    return to_jstring(env, output.str());
}
