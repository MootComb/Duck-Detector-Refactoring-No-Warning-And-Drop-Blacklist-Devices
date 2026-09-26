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

#include "virtualization/snapshot_builder.h"

#include <set>
#include <string>
#include <vector>

// The pieces of the snapshot builder that its translation units share. They are not part of the
// unit's interface, which snapshot_builder.h declares.
namespace duckdetector::virtualization::snapshot_scan {

    bool contains_token(const std::string &text, const std::vector<std::string> &tokens);

    void add_finding(
            Snapshot &snapshot,
            std::set<std::string> &dedupe,
            SnapshotGroup group,
            const std::string &severity,
            const std::string &label,
            const std::string &value,
            const std::string &detail,
            EarlySignal earlySignal = EarlySignal::kNone
    );

    // The views of this process's own state: its memory maps, mounts, mount namespace and open
    // file descriptors.
    void scan_maps(Snapshot &snapshot, std::set<std::string> &dedupe);

    void scan_mountinfo(Snapshot &snapshot, std::set<std::string> &dedupe);

    void scan_mount_namespace(Snapshot &snapshot);

    void scan_fd_targets(Snapshot &snapshot, std::set<std::string> &dedupe);

}  // namespace duckdetector::virtualization::snapshot_scan
