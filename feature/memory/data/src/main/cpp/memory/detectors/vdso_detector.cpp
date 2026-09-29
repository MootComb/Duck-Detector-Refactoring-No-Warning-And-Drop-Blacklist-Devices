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

#include "memory/detectors/vdso_detector.h"

#include <sys/auxv.h>

#include <sstream>

namespace duckdetector::memory {

    VdsoSignals detect_vdso_anomalies(const std::vector<MapEntry> &maps) {
        VdsoSignals signals;
        std::vector<MapEntry> vdso_entries;
        for (const MapEntry &entry: maps) {
            if (entry.path == "[vdso]") {
                vdso_entries.push_back(entry);
            }
        }

        const auto auxv_base = static_cast<std::uintptr_t>(::getauxval(AT_SYSINFO_EHDR));
        // The kernel passes AT_SYSINFO_EHDR only for a vDSO it mapped, and bionic falls back to
        // syscalls without one. arm64 kernels always map one for AArch64 processes, but 32-bit
        // processes get none on arm64 kernels built without CONFIG_COMPAT_VDSO or on arm kernels
        // without CONFIG_VDSO, and x86 kernels can have it disabled with vdso= or vdso32=.
        // https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/arch/arm64/kernel/vdso.c
        // https://android.googlesource.com/platform/bionic/+/refs/heads/main/libc/bionic/vdso.cpp
#if defined(__aarch64__)
        constexpr bool kernel_may_omit_vdso = false;
#else
        constexpr bool kernel_may_omit_vdso = true;
#endif
        if (kernel_may_omit_vdso && auxv_base == 0 && vdso_entries.empty()) {
            return signals;
        }
        signals.checks_ran = true;

        if (vdso_entries.size() != 1U) {
            signals.remapped = true;
            std::ostringstream detail;
            detail << "Expected 1 [vdso] mapping but saw " << vdso_entries.size()
                   << " (AT_SYSINFO_EHDR=0x" << std::hex << auxv_base << ")";
            signals.findings.push_back(
                    Finding{
                            .section = "VDSO",
                            .category = "VDSO",
                            .label = "Unexpected [vdso] mapping count",
                            .detail = detail.str(),
                            .severity = FindingSeverity::kHigh,
                    }
            );
            return signals;
        }

        const MapEntry &entry = vdso_entries.front();
        if (entry.writable) {
            signals.remapped = true;
            std::ostringstream detail;
            detail << "[vdso] is writable at 0x" << std::hex << entry.start << "-0x" << entry.end;
            signals.findings.push_back(
                    Finding{
                            .section = "VDSO",
                            .category = "VDSO",
                            .label = "Writable [vdso] mapping",
                            .detail = detail.str(),
                            .severity = FindingSeverity::kHigh,
                    }
            );
        }

        if (auxv_base != 0 && auxv_base != entry.start) {
            signals.unusual_base = true;
            std::ostringstream detail;
            detail << "AT_SYSINFO_EHDR=0x" << std::hex << auxv_base
                   << " but [vdso] starts at 0x" << entry.start;
            signals.findings.push_back(
                    Finding{
                            .section = "VDSO",
                            .category = "VDSO",
                            .label = "vDSO base mismatch",
                            .detail = detail.str(),
                            .severity = FindingSeverity::kMedium,
                    }
            );
        }

        return signals;
    }

}  // namespace duckdetector::memory
