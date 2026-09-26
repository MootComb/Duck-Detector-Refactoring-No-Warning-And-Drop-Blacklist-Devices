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

#include "systemproperties/prop_area_probe.h"

#include "systemproperties/prop_area_file.h"

#include <dirent.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace systemproperties {
    namespace {

        constexpr size_t kMaxHoleSamples = 3;

        struct ParsedAreaResult {
            bool parsed = false;
            std::optional<PropAreaFinding> finding;
        };

        std::string hex_offset(uint32_t offset) {
            std::ostringstream stream;
            stream << "0x" << std::hex << std::nouppercase << offset;
            return stream.str();
        }

        std::optional<ParsedAreaResult>
        scan_area(const std::string &path, const std::string &context) {
            // bionic reserves the dirty backup area only from Android 11, yet this scan marks it
            // on every release; docs/architecture/follow-ups.md tracks matching the custom ROM
            // probe, which marks it from API 30.
            const auto holes = scan_prop_area_file(path, /*mark_dirty_backup=*/true);
            if (!holes.has_value()) {
                return std::nullopt;
            }

            ParsedAreaResult result;
            result.parsed = true;
            if (!holes->empty()) {
                std::ostringstream detail;
                detail << "Found hole in prop area: " << context;
                detail << " (" << holes->size() << " hole(s))";
                detail << " ranges ";
                const size_t sample_count = std::min(holes->size(), kMaxHoleSamples);
                for (size_t index = 0; index < sample_count; ++index) {
                    if (index > 0) {
                        detail << ", ";
                    }
                    detail << '@' << hex_offset((*holes)[index].offset) << '+'
                           << (*holes)[index].length;
                }
                if (holes->size() > sample_count) {
                    detail << ", ...";
                }
                result.finding = PropAreaFinding{
                        .context = context,
                        .hole_count = static_cast<int>(holes->size()),
                        .detail = detail.str(),
                };
            }
            return result;
        }

    }  // namespace

    PropAreaSnapshot scan_prop_area_holes() {
        PropAreaSnapshot snapshot;

        DIR *directory = opendir(kPropDir);
        if (directory == nullptr) {
            return snapshot;
        }

        while (dirent *entry = readdir(directory)) {
            if (is_skipped_entry(entry->d_name)) {
                continue;
            }

            const std::string context(entry->d_name);
            const std::string path = std::string(kPropDir) + "/" + context;
            const auto finding = scan_area(path, context);
            if (!finding.has_value()) {
                continue;
            }

            snapshot.available = true;
            ++snapshot.context_count;
            if (finding->finding.has_value()) {
                snapshot.hole_count += finding->finding->hole_count;
                snapshot.findings.push_back(*finding->finding);
            }
        }

        closedir(directory);
        return snapshot;
    }

}  // namespace systemproperties
