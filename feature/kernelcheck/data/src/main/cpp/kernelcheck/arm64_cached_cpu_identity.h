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

#include "kernelcheck/arm64_cpu_identity_probe.h"

namespace duckdetector::kernelcheck {

    /**
     * Fills the cached identity of observation->cpu: its regs/identification/midr_el1 sysfs node
     * when readable, otherwise the MIDR fields of its /proc/cpuinfo block. Both print
     * cpu_data[cpu].reg_midr, which arch/arm64/kernel/cpuinfo.c stores when the CPU comes online,
     * so they are one source rather than two independent ones.
     */
    void collect_cached_cpu_identity(CpuIdentityObservation *observation);

}  // namespace duckdetector::kernelcheck
