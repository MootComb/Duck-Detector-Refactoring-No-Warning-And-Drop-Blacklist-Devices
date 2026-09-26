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

#include "tee/trickystore/trickystore_internal.h"

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

namespace ducktee::trickystore::detail {

    LibInfo find_library(const std::string &needle) {
        LibInfo info;
        std::ifstream maps("/proc/self/maps");
        if (!maps.is_open()) {
            return info;
        }

        std::string line;
        while (std::getline(maps, line)) {
            if (line.find(needle) == std::string::npos) {
                continue;
            }
            const std::size_t dash = line.find('-');
            if (dash == std::string::npos) {
                continue;
            }

            uintptr_t address = 0;
            for (std::size_t index = 0; index < dash; ++index) {
                const char ch = line[index];
                address <<= 4;
                if (ch >= '0' && ch <= '9') {
                    address |= static_cast<uintptr_t>(ch - '0');
                } else if (ch >= 'a' && ch <= 'f') {
                    address |= static_cast<uintptr_t>(ch - 'a' + 10);
                } else if (ch >= 'A' && ch <= 'F') {
                    address |= static_cast<uintptr_t>(ch - 'A' + 10);
                }
            }

            const std::size_t path_start = line.find('/');
            if (path_start == std::string::npos) {
                continue;
            }

            info.base = address;
            info.path = line.substr(path_start);
            while (!info.path.empty() && info.path.back() <= ' ') {
                info.path.pop_back();
            }
            info.found = true;
            break;
        }
        return info;
    }

    MapAccess find_map_access_for_address(const uintptr_t address) {
        MapAccess access;
        std::ifstream maps("/proc/self/maps");
        if (!maps.is_open()) {
            return access;
        }

        std::string line;
        while (std::getline(maps, line)) {
            unsigned long long start = 0;
            unsigned long long end = 0;
            char perms[5] = {};
            if (std::sscanf(line.c_str(), "%llx-%llx %4s", &start, &end, perms) != 3) {
                continue;
            }
            if (address < start || address >= end) {
                continue;
            }
            access.found = true;
            access.readable = perms[0] == 'r';
            return access;
        }
        return access;
    }

    bool maps_contain_trickystore(std::vector<std::string> *findings) {
        std::ifstream maps("/proc/self/maps");
        if (!maps.is_open()) {
            return false;
        }

        bool matched = false;
        std::string line;
        while (std::getline(maps, line)) {
            if (line.find("tricky") != std::string::npos ||
                line.find("keystore_interceptor") != std::string::npos) {
                matched = true;
                if (findings != nullptr) {
                    findings->push_back(line);
                }
            }
        }
        return matched;
    }

}  // namespace ducktee::trickystore::detail
