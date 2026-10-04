/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

#include "kernelcheck/arm64_cached_cpu_identity.h"

#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/syscall.h>
#include <unistd.h>

namespace duckdetector::kernelcheck {

    namespace {

        std::string read_file(const std::string &path, std::size_t limit = 128 * 1024) {
            const int fd = static_cast<int>(syscall(
                    __NR_openat,
                    AT_FDCWD,
                    path.c_str(),
                    O_RDONLY | O_CLOEXEC,
                    0
            ));
            if (fd < 0) {
                return "";
            }

            std::string content;
            char buffer[4096];
            ssize_t bytes_read = 0;
            while (content.size() < limit &&
                   (bytes_read = syscall(__NR_read, fd, buffer, sizeof(buffer))) > 0) {
                content.append(buffer, static_cast<std::size_t>(bytes_read));
            }
            syscall(__NR_close, fd);
            return content;
        }

        std::string trim_copy(std::string_view value) {
            const std::size_t first = value.find_first_not_of(" \t\r\n");
            if (first == std::string_view::npos) {
                return "";
            }
            const std::size_t last = value.find_last_not_of(" \t\r\n");
            return std::string(value.substr(first, last - first + 1));
        }

        std::optional<std::uint32_t> parse_number(
                const std::string &value,
                int default_base
        ) {
            const std::string trimmed = trim_copy(value);
            if (trimmed.empty()) {
                return std::nullopt;
            }

            char *end = nullptr;
            errno = 0;
            const unsigned long parsed = std::strtoul(trimmed.c_str(), &end, default_base);
            if (errno != 0 || end == trimmed.c_str() || *end != '\0' || parsed > UINT32_MAX) {
                return std::nullopt;
            }
            return static_cast<std::uint32_t>(parsed);
        }

        std::optional<std::uint32_t> read_sysfs_midr(int cpu) {
            const std::string path = "/sys/devices/system/cpu/cpu" + std::to_string(cpu) +
                                     "/regs/identification/midr_el1";
            const std::string raw = trim_copy(read_file(path, 128));
            if (raw.empty()) {
                return std::nullopt;
            }
            const int base = raw.starts_with("0x") || raw.starts_with("0X") ? 0 : 16;
            return parse_number(raw, base);
        }

        struct ProcMidrFields {
            std::optional<std::uint32_t> implementer;
            std::optional<std::uint32_t> variant;
            std::optional<std::uint32_t> part;
            std::optional<std::uint32_t> revision;

            std::optional<std::uint32_t> to_midr() const {
                if (!implementer || !variant || !part || !revision ||
                    *implementer > 0xff || *variant > 0xf || *part > 0xfff || *revision > 0xf) {
                    return std::nullopt;
                }
                return (*implementer << 24U) |
                       (*variant << 20U) |
                       (*part << 4U) |
                       *revision;
            }
        };

        std::optional<std::uint32_t> read_proc_cpuinfo_midr(int target_cpu) {
            std::istringstream input(read_file("/proc/cpuinfo"));
            std::string line;
            int current_cpu = -1;
            ProcMidrFields fields;

            const auto finish_block = [&]() -> std::optional<std::uint32_t> {
                return current_cpu == target_cpu ? fields.to_midr() : std::nullopt;
            };

            while (std::getline(input, line)) {
                if (trim_copy(line).empty()) {
                    if (const auto midr = finish_block()) {
                        return midr;
                    }
                    current_cpu = -1;
                    fields = ProcMidrFields{};
                    continue;
                }

                const std::size_t separator = line.find(':');
                if (separator == std::string::npos) {
                    continue;
                }
                const std::string key = trim_copy(std::string_view(line).substr(0, separator));
                const std::string value = trim_copy(std::string_view(line).substr(separator + 1));
                if (key == "processor") {
                    const auto parsed = parse_number(value, 10);
                    current_cpu = parsed ? static_cast<int>(*parsed) : -1;
                } else if (current_cpu == target_cpu && key == "CPU implementer") {
                    fields.implementer = parse_number(value, 0);
                } else if (current_cpu == target_cpu && key == "CPU variant") {
                    fields.variant = parse_number(value, 0);
                } else if (current_cpu == target_cpu && key == "CPU part") {
                    fields.part = parse_number(value, 0);
                } else if (current_cpu == target_cpu && key == "CPU revision") {
                    fields.revision = parse_number(value, 0);
                }
            }
            return finish_block();
        }

    }  // namespace

    void collect_cached_cpu_identity(CpuIdentityObservation *observation) {
        observation->cached_midr = read_sysfs_midr(observation->cpu);
        if (observation->cached_midr) {
            observation->cached_source = CachedCpuIdentitySource::Sysfs;
            return;
        }

        observation->cached_midr = read_proc_cpuinfo_midr(observation->cpu);
        if (observation->cached_midr) {
            observation->cached_source = CachedCpuIdentitySource::ProcCpuinfo;
        }
    }

}  // namespace duckdetector::kernelcheck
