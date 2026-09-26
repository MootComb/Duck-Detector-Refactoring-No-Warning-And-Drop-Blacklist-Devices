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

#include "tee/trickystore/trickystore_probe.h"
#include <algorithm>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include "tee/common/local_timer.h"
#include "tee/common/syscall_facade.h"
#include "tee/common/timing_stats.h"

namespace ducktee::trickystore::detail {

#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)

#define BINDER_VERSION _IOWR('b', 9, struct binder_version)

#define BC_TRANSACTION _IOW('c', 0, struct binder_transaction_data)

    struct binder_write_read {
        signed long write_size;
        signed long write_consumed;
        unsigned long write_buffer;
        signed long read_size;
        signed long read_consumed;
        unsigned long read_buffer;
    };

    struct binder_version {
        signed long protocol_version;
    };

    struct binder_transaction_data {
        union {
            unsigned int handle;
            void *ptr;
        } target;
        void *cookie;
        unsigned int code;
        unsigned int flags;
        int sender_pid;
        unsigned int sender_euid;
        unsigned long data_size;
        unsigned long offsets_size;
        union {
            struct {
                unsigned long buffer;
                unsigned long offsets;
            } ptr;
            unsigned char buf[8];
        } data;
    };

    struct MethodSnapshot {
        bool detected = false;
        std::string detail;
        std::vector<std::string> findings;
        int honeypot_run_count = 0;
        int honeypot_suspicious_run_count = 0;
        std::uint64_t honeypot_median_gap_ns = 0;
        std::uint64_t honeypot_gap_mad_ns = 0;
        std::uint64_t honeypot_median_noise_floor_ns = 0;
        int honeypot_median_ratio_percent = 0;
        std::string timer_source = "unknown";
        std::string timer_fallback_reason;
        std::string affinity_status = "not_requested";
    };

    struct LibInfo {
        uintptr_t base = 0;
        std::string path;
        bool found = false;
    };

    struct MapAccess {
        bool found = false;
        bool readable = false;
    };

    constexpr int kHoneypotIterations = 40;

    constexpr std::uint64_t kHoneypotBaseGapThresholdNs = 10'000ULL;

    constexpr std::uint64_t kHoneypotNoiseMultiplier = 6ULL;

    constexpr std::uint64_t kHoneypotRatioThresholdPercent = 150ULL;

    constexpr int kRepeatedProbeAttempts = 3;

    constexpr std::array<ducktee::common::SyscallBackend, 3> kIoctlBackends = {
            ducktee::common::SyscallBackend::Libc,
            ducktee::common::SyscallBackend::Syscall,
            ducktee::common::SyscallBackend::Asm,
    };

    class ScopedThreadAffinityRestore {
    public:
        ScopedThreadAffinityRestore() = default;
        ScopedThreadAffinityRestore(const ScopedThreadAffinityRestore &) = delete;
        ScopedThreadAffinityRestore &operator=(const ScopedThreadAffinityRestore &) = delete;

        ~ScopedThreadAffinityRestore() {
            if (armed_) {
                (void) ducktee::common::restore_current_thread_affinity();
            }
        }

        void arm(bool affinity_bound) {
            armed_ = affinity_bound;
        }

    private:
        bool armed_ = false;
    };

    struct IoctlBackendObservation {
        ducktee::common::SyscallBackend backend = ducktee::common::SyscallBackend::Libc;
        long result = -1;
        int error_number = 0;
        int protocol_version = 0;
    };

    struct HoneypotTimingPath {
        ducktee::common::SyscallBackend backend = ducktee::common::SyscallBackend::Libc;
        bool available = false;
        std::vector<std::uint64_t> samples;
        ducktee::common::SampleStats stats;
        std::string failure;

        [[nodiscard]] std::uint64_t median_ns() const {
            return stats.median_ns;
        }
    };

    struct HoneypotRunSummary {
        bool suspicious = false;
        bool libc_available = false;
        bool lower_found = false;
        bool stable_lower_paths = false;
        std::uint64_t libc_median_ns = 0;
        std::uint64_t fastest_lower_median_ns = 0;
        std::uint64_t gap_ns = 0;
        std::uint64_t noise_floor_ns = 0;
        std::uint64_t ratio_percent = 0;
        std::string path_summary;
    };

    int raw_open(const char *path, int flags);

    int open_binder_device();

    std::vector<ducktee::common::SyscallBackend> available_backends();

    std::vector<ducktee::common::SyscallBackend> rotated_available_backends(const int attempt);

    ducktee::common::SyscallCallResult call_ioctl_backend(
            const ducktee::common::SyscallBackend backend,
            const int fd,
            const unsigned long request,
            void *arg
    );

    std::string format_backend_observation(const IoctlBackendObservation &observation);

    bool backend_samples_aligned(
            const IoctlBackendObservation &reference,
            const IoctlBackendObservation &candidate
    );

    void prepare_honeypot_payload(
            std::uint8_t *write_buffer,
            binder_write_read *bwr,
            std::uint8_t *fake_data
    );

    bool collect_honeypot_backend_samples(
            const int binder_fd,
            const ducktee::common::LocalTimerSelection &timer,
            HoneypotTimingPath *path
    );

    bool lower_paths_are_stable(const std::vector<HoneypotTimingPath> &paths);

    std::string describe_honeypot_path(const HoneypotTimingPath &path);

    std::string describe_honeypot_paths(const std::vector<HoneypotTimingPath> &paths);

    HoneypotRunSummary analyze_honeypot_paths(const std::vector<HoneypotTimingPath> &paths);

    LibInfo find_library(const std::string &needle);

    MapAccess find_map_access_for_address(const uintptr_t address);

    bool maps_contain_trickystore(std::vector<std::string> *findings);

#if defined(__LP64__)
    using ElfWord_Ehdr = Elf64_Ehdr;
    using ElfWord_Phdr = Elf64_Phdr;
    using ElfWord_Dyn = Elf64_Dyn;
    using ElfWord_Sym = Elf64_Sym;
    using ElfWord_Rela = Elf64_Rela;
    using ElfWord_Addr = Elf64_Addr;
#define DUCK_ELF_R_SYM(value) ELF64_R_SYM(value)
#define DUCK_ELF_R_TYPE(value) ELF64_R_TYPE(value)
#define DUCK_R_JUMP_SLOT R_AARCH64_JUMP_SLOT
#if defined(__x86_64__)
#undef DUCK_R_JUMP_SLOT
#define DUCK_R_JUMP_SLOT R_X86_64_JUMP_SLOT
#endif
#else
    using ElfWord_Ehdr = Elf32_Ehdr;
    using ElfWord_Phdr = Elf32_Phdr;
    using ElfWord_Dyn = Elf32_Dyn;
    using ElfWord_Sym = Elf32_Sym;
    using ElfWord_Rela = Elf32_Rel;
    using ElfWord_Addr = Elf32_Addr;
#define DUCK_ELF_R_SYM(value) ELF32_R_SYM(value)
#define DUCK_ELF_R_TYPE(value) ELF32_R_TYPE(value)
#define DUCK_R_JUMP_SLOT R_ARM_JUMP_SLOT
#if defined(__i386__)
#undef DUCK_R_JUMP_SLOT
#define DUCK_R_JUMP_SLOT R_386_JMP_SLOT
#endif
#endif

    MethodSnapshot detect_got_ioctl_hook();

    MethodSnapshot run_single_syscall_ioctl_mismatch_probe();

    MethodSnapshot detect_syscall_ioctl_mismatch();

    MethodSnapshot detect_ioctl_inline_hook();

    MethodSnapshot run_single_ioctl_honeypot_probe(const int attempt);

    MethodSnapshot detect_ioctl_honeypot();

}  // namespace ducktee::trickystore::detail
