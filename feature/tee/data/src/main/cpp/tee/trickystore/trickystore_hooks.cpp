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

#include "tee/trickystore/trickystore_probe.h"
#include "tee/trickystore/trickystore_internal.h"
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
#include "tee/common/syscall_facade.h"
#include "tee/common/timing_stats.h"

namespace ducktee::trickystore::detail {

    MethodSnapshot detect_got_ioctl_hook() {
        MethodSnapshot snapshot;

        void *real_ioctl = dlsym(RTLD_DEFAULT, "ioctl");
        if (real_ioctl == nullptr) {
            snapshot.detail = "Failed to resolve ioctl via dlsym.";
            return snapshot;
        }

        const LibInfo binder = find_library("libbinder.so");
        if (!binder.found || binder.path.empty()) {
            snapshot.detail = "libbinder.so not found in process maps.";
            return snapshot;
        }

        const int fd = raw_open(binder.path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            snapshot.detail = "Failed to open libbinder.so for GOT inspection.";
            return snapshot;
        }

        ElfWord_Ehdr ehdr{};
        if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr) ||
            std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
            close(fd);
            snapshot.detail = "Failed to read a valid ELF header from libbinder.so.";
            return snapshot;
        }

        std::vector<ElfWord_Phdr> phdrs(ehdr.e_phnum);
        lseek(fd, ehdr.e_phoff, SEEK_SET);
        const auto phdr_bytes = sizeof(ElfWord_Phdr) * static_cast<std::size_t>(ehdr.e_phnum);
        if (read(fd, phdrs.data(), phdr_bytes) != static_cast<ssize_t>(phdr_bytes)) {
            close(fd);
            snapshot.detail = "Failed to read libbinder.so program headers.";
            return snapshot;
        }
        close(fd);

        ElfWord_Addr dyn_vaddr = 0;
        for (const auto &phdr: phdrs) {
            if (phdr.p_type == PT_DYNAMIC) {
                dyn_vaddr = phdr.p_vaddr;
                break;
            }
        }
        if (dyn_vaddr == 0) {
            snapshot.detail = "PT_DYNAMIC segment missing from libbinder.so.";
            return snapshot;
        }

        auto *dyn_base = reinterpret_cast<ElfWord_Dyn *>(binder.base + dyn_vaddr);
        ElfWord_Addr jmprel = 0;
        ElfWord_Addr pltrelsz = 0;
        ElfWord_Addr symtab_addr = 0;
        ElfWord_Addr strtab_addr = 0;

        for (auto *dyn = dyn_base; dyn->d_tag != DT_NULL; ++dyn) {
            switch (dyn->d_tag) {
                case DT_JMPREL:
                    jmprel = dyn->d_un.d_ptr;
                    break;
                case DT_PLTRELSZ:
                    pltrelsz = dyn->d_un.d_val;
                    break;
                case DT_SYMTAB:
                    symtab_addr = dyn->d_un.d_ptr;
                    break;
                case DT_STRTAB:
                    strtab_addr = dyn->d_un.d_ptr;
                    break;
                default:
                    break;
            }
        }

        if (jmprel != 0 && jmprel < binder.base) {
            jmprel += binder.base;
        }
        if (symtab_addr != 0 && symtab_addr < binder.base) {
            symtab_addr += binder.base;
        }
        if (strtab_addr != 0 && strtab_addr < binder.base) {
            strtab_addr += binder.base;
        }

        if (jmprel == 0 || pltrelsz == 0 || symtab_addr == 0 || strtab_addr == 0) {
            snapshot.detail = "libbinder.so was missing PLT relocation metadata for ioctl.";
            return snapshot;
        }

        auto *rels = reinterpret_cast<ElfWord_Rela *>(jmprel);
        auto *symtab = reinterpret_cast<ElfWord_Sym *>(symtab_addr);
        auto *strtab = reinterpret_cast<const char *>(strtab_addr);
        const std::size_t rel_count = pltrelsz / sizeof(ElfWord_Rela);

        for (std::size_t index = 0; index < rel_count; ++index) {
            const unsigned long sym_index = DUCK_ELF_R_SYM(rels[index].r_info);
            const unsigned long rel_type = DUCK_ELF_R_TYPE(rels[index].r_info);
            if (rel_type != DUCK_R_JUMP_SLOT) {
                continue;
            }

            const char *symbol_name = strtab + symtab[sym_index].st_name;
            if (std::strcmp(symbol_name, "ioctl") != 0) {
                continue;
            }

            auto *got_entry = reinterpret_cast<void **>(binder.base + rels[index].r_offset);
            void *got_value = *got_entry;
            if (got_value != real_ioctl) {
                snapshot.detected = true;
                Dl_info dl_info{};
                std::string hook_library = "unknown";
                if (dladdr(got_value, &dl_info) && dl_info.dli_fname != nullptr) {
                    hook_library = dl_info.dli_fname;
                }
                std::ostringstream builder;
                builder << "libbinder.so ioctl GOT entry resolved to " << got_value
                        << " instead of libc ioctl " << real_ioctl
                        << " (hook library: " << hook_library << ").";
                snapshot.findings.push_back(builder.str());
                snapshot.detail = "GOT hook detected on ioctl in libbinder.so.";
            } else {
                snapshot.detail = "libbinder.so ioctl GOT entry matched libc.";
            }
            return snapshot;
        }

        snapshot.detail = "ioctl relocation was not found in libbinder.so.";
        return snapshot;
    }

    MethodSnapshot run_single_syscall_ioctl_mismatch_probe() {
        MethodSnapshot snapshot;
        const int binder_fd = open_binder_device();
        if (binder_fd < 0) {
            snapshot.detail = "Cannot open binder device for ioctl backend comparison.";
            return snapshot;
        }

        std::vector<IoctlBackendObservation> observations;
        for (const auto backend: available_backends()) {
            binder_version version{};
            const auto result = call_ioctl_backend(backend, binder_fd, BINDER_VERSION,
                                                   &version);
            if (!result.available) {
                continue;
            }
            observations.push_back(IoctlBackendObservation{
                    .backend = backend,
                    .result = result.value,
                    .error_number = result.error_number,
                    .protocol_version = static_cast<int>(version.protocol_version),
            });
        }
        close(binder_fd);

        if (observations.size() < 2) {
            snapshot.detail = "Fewer than two ioctl backends were available for binder comparison.";
            return snapshot;
        }

        const auto &reference = observations.front();
        for (std::size_t index = 1; index < observations.size(); ++index) {
            if (backend_samples_aligned(reference, observations[index])) {
                continue;
            }
            snapshot.detected = true;
            std::ostringstream builder;
            builder << "Binder version query diverged across backends: "
                    << format_backend_observation(reference) << " vs "
                    << format_backend_observation(observations[index]) << ".";
            snapshot.findings.push_back(builder.str());
            snapshot.detail = "Binder version query returned different results across libc/syscall/asm backends.";
            return snapshot;
        }

        std::ostringstream builder;
        builder << "Binder version query aligned across ";
        for (std::size_t index = 0; index < observations.size(); ++index) {
            if (index > 0) {
                builder << ", ";
            }
            builder << ducktee::common::backend_label(observations[index].backend);
        }
        builder << " backends.";
        snapshot.detail = builder.str();
        return snapshot;
    }

    MethodSnapshot detect_syscall_ioctl_mismatch() {
        MethodSnapshot snapshot;
        int hit_count = 0;
        std::string last_detail;

        for (int attempt = 0; attempt < kRepeatedProbeAttempts; ++attempt) {
            const MethodSnapshot single = run_single_syscall_ioctl_mismatch_probe();
            if (!single.detail.empty()) {
                last_detail = single.detail;
            }
            if (!single.detected) {
                continue;
            }
            ++hit_count;
            if (snapshot.findings.empty()) {
                snapshot.findings = single.findings;
            }
        }

        snapshot.detected = hit_count >= 2;
        std::ostringstream builder;
        if (snapshot.detected) {
            builder << "Binder version ioctl diverged on " << hit_count
                    << "/" << kRepeatedProbeAttempts << " backend-comparison probes.";
            snapshot.detail = builder.str();
        } else {
            builder << "Binder version ioctl stayed aligned across "
                    << kRepeatedProbeAttempts << " backend-comparison probes";
            if (hit_count > 0) {
                builder << " (" << hit_count << "/" << kRepeatedProbeAttempts
                        << " suspicious run).";
            } else {
                builder << ".";
            }
            if (!last_detail.empty()) {
                builder << " " << last_detail;
            }
            snapshot.detail = builder.str();
        }
        return snapshot;
    }

    MethodSnapshot detect_ioctl_inline_hook() {
        MethodSnapshot snapshot;

        void *ioctl_addr = dlsym(RTLD_DEFAULT, "ioctl");
        if (ioctl_addr == nullptr) {
            snapshot.detail = "Failed to resolve ioctl for inline hook inspection.";
            return snapshot;
        }

        Dl_info ioctl_info{};
        if (!dladdr(ioctl_addr, &ioctl_info) || ioctl_info.dli_fname == nullptr) {
            snapshot.detail = "Failed to resolve the backing library for ioctl.";
            return snapshot;
        }

        const MapAccess ioctl_map =
                find_map_access_for_address(reinterpret_cast<uintptr_t>(ioctl_addr));
        if (!ioctl_map.found || !ioctl_map.readable) {
            snapshot.detail =
                    "Skipped ioctl inline hook inspection because the resolved code page is not readable.";
            return snapshot;
        }

        std::uint8_t memory_prologue[16];
        std::memcpy(memory_prologue, ioctl_addr, sizeof(memory_prologue));

        const LibInfo lib_info = find_library(ioctl_info.dli_fname);
        if (!lib_info.found) {
            snapshot.detail = "Could not locate ioctl library in process maps.";
            return snapshot;
        }

        const int fd = raw_open(ioctl_info.dli_fname, O_RDONLY | O_CLOEXEC);
        bool compared_on_disk = false;
        if (fd >= 0) {
            ElfWord_Ehdr ehdr{};
            if (read(fd, &ehdr, sizeof(ehdr)) == sizeof(ehdr) &&
                std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) == 0) {
                std::vector<ElfWord_Phdr> phdrs(ehdr.e_phnum);
                lseek(fd, ehdr.e_phoff, SEEK_SET);
                const auto phdr_bytes =
                        sizeof(ElfWord_Phdr) * static_cast<std::size_t>(ehdr.e_phnum);
                if (read(fd, phdrs.data(), phdr_bytes) == static_cast<ssize_t>(phdr_bytes)) {
                    const uintptr_t ioctl_va =
                            reinterpret_cast<uintptr_t>(ioctl_addr) - lib_info.base;
                    for (const auto &phdr: phdrs) {
                        if (phdr.p_type != PT_LOAD) {
                            continue;
                        }
                        if (ioctl_va >= phdr.p_vaddr &&
                            ioctl_va < phdr.p_vaddr + phdr.p_filesz) {
                            const uintptr_t file_offset =
                                    phdr.p_offset + (ioctl_va - phdr.p_vaddr);
                            std::uint8_t disk_prologue[16];
                            lseek(fd, static_cast<off_t>(file_offset), SEEK_SET);
                            if (read(fd, disk_prologue, sizeof(disk_prologue)) ==
                                sizeof(disk_prologue)) {
                                compared_on_disk = true;
                                if (!ducktee::common::bytes_equal(memory_prologue,
                                                                  disk_prologue,
                                                                  sizeof(memory_prologue))) {
                                    snapshot.detected = true;
                                    std::ostringstream builder;
                                    builder
                                            << "In-memory ioctl prologue differed from the on-disk image.";
                                    snapshot.findings.push_back(builder.str());
                                    snapshot.detail = "Inline hook detected on ioctl.";
                                }
                            }
                            break;
                        }
                    }
                }
            }
            close(fd);
        }

#if defined(__aarch64__)
        if (!snapshot.detected) {
            auto* instructions = reinterpret_cast<const std::uint32_t*>(ioctl_addr);
            for (int index = 0; index < 4; ++index) {
                const std::uint32_t word = instructions[index];
                if ((word & 0xFC000000U) == 0x14000000U && index == 0) {
                    const std::int32_t imm26 = static_cast<std::int32_t>(word << 6) >> 6;
                    const uintptr_t target = reinterpret_cast<uintptr_t>(&instructions[index]) + static_cast<uintptr_t>(imm26 * 4);
                    Dl_info target_info{};
                    if (dladdr(reinterpret_cast<void*>(target), &target_info) &&
                        target_info.dli_fname != nullptr &&
                        std::string(target_info.dli_fname) != std::string(ioctl_info.dli_fname)) {
                        snapshot.detected = true;
                        snapshot.findings.push_back("ioctl begins with an unconditional branch into another library.");
                        snapshot.detail = "Inline hook detected via external branch trampoline.";
                        break;
                    }
                }
                if ((word & 0xFFFFFC1FU) == 0xD61F0000U && index < 2) {
                    snapshot.detected = true;
                    snapshot.findings.push_back("ioctl prologue contained a BR register jump.");
                    snapshot.detail = "Inline hook detected via BR trampoline.";
                    break;
                }
            }
        }
#endif

        if (!snapshot.detected) {
            snapshot.detail = compared_on_disk
                              ? "ioctl prologue matched the on-disk image."
                              : "Could not compare the ioctl prologue with the on-disk image.";
        }
        return snapshot;
    }

}  // namespace ducktee::trickystore::detail
