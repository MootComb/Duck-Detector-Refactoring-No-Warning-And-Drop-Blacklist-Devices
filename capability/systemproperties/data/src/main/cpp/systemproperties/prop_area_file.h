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

#include "systemproperties/prop_area_parser.h"

#include <optional>
#include <string>
#include <vector>

namespace systemproperties {

    // init creates one property area per SELinux context in this directory.
    constexpr const char *kPropDir = "/dev/__properties__";

    // True for the entries of kPropDir that are not property areas.
    bool is_skipped_entry(const char *name);

    // Maps a property area read-only and walks it once its header carries bionic's magic and
    // version and a bytes_used that fits the file and holds the root node, plus the dirty backup
    // area when that is marked. Returns the holes, or nullopt when the file is not a regular file,
    // cannot be mapped, fails those checks or does not parse.
    std::optional<std::vector<HoleRun>> scan_prop_area_file(
            const std::string &path,
            bool mark_dirty_backup,
            const PropAreaParser::PropertyVisitor &visit_property = {}
    );

}  // namespace systemproperties
