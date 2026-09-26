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

#include <string>
#include <vector>

namespace customrom {

    struct PropertyIntegrityFinding {
        std::string category;
        std::string signal;
        std::string summary;
        std::string detail;
    };

    struct PropertyIntegritySnapshot {
        bool available = false;
        int context_count = 0;
        int area_anomaly_count = 0;
        int item_anomaly_count = 0;
        std::vector<PropertyIntegrityFinding> findings;
    };

    PropertyIntegritySnapshot scan_property_integrity();

}  // namespace customrom
