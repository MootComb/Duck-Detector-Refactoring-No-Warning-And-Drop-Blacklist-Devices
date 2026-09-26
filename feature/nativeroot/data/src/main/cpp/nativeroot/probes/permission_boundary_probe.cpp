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

#include "nativeroot/probes/permission_boundary_probe.h"

#include "nativeroot/probes/permission_boundary_netlink.h"

#include <android/api-level.h>

namespace duckdetector::nativeroot {

    using permission_boundary::check_netlink_link_boundary;
    using permission_boundary::check_netlink_neigh_boundary;

    ProbeResult run_permission_boundary_check() {
        ProbeResult result;
        const int api_level = android_get_device_api_level();
        const int target_sdk = android_get_application_target_sdk_version();

        check_netlink_link_boundary(result, api_level, target_sdk);
        check_netlink_neigh_boundary(result, api_level, target_sdk);

        return result;
    }

}  // namespace duckdetector::nativeroot
