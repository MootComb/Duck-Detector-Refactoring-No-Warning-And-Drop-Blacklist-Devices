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

#include "customrom/symbol_probe.h"

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace customrom {
    namespace {

        bool path_exists(const char *path) {
            struct stat st {};
            return stat(path, &st) == 0;
        }

        std::vector<std::string> find_library_paths(const char *library_name) {
            std::vector<std::string> paths;
            std::set<std::string> unique_paths;

            const int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                return paths;
            }

            std::string content;
            char buffer[4096];
            ssize_t bytes_read = 0;
            while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
                content.append(buffer, static_cast<size_t>(bytes_read));
            }
            close(fd);

            if (bytes_read < 0) {
                return paths;
            }

            std::istringstream stream(content);
            std::string line;
            while (std::getline(stream, line)) {
                if (line.find(library_name) == std::string::npos) {
                    continue;
                }
                const size_t path_start = line.find('/');
                if (path_start == std::string::npos) {
                    continue;
                }
                std::string path = line.substr(path_start);
                const std::string deleted_suffix = " (deleted)";
                if (path.size() > deleted_suffix.size() &&
                    path.ends_with(deleted_suffix)) {
                    path.erase(path.size() - deleted_suffix.size());
                }
                if (!path.ends_with(library_name)) {
                    continue;
                }
                if (path.starts_with("/system/") || path.starts_with("/apex/")) {
                    if (path_exists(path.c_str()) && unique_paths.insert(path).second) {
                        paths.emplace_back(std::move(path));
                    }
                }
            }

            return paths;
        }

#if defined(__LP64__)
        using ElfHeader = Elf64_Ehdr;
        using ElfSection = Elf64_Shdr;
        using ElfSymbol = Elf64_Sym;
#else
        using ElfHeader = Elf32_Ehdr;
        using ElfSection = Elf32_Shdr;
        using ElfSymbol = Elf32_Sym;
#endif

        bool contains_symbol_in_file(const std::string &path, const char *symbol_name) {
            const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                return false;
            }

            struct stat st {};
            if (fstat(fd, &st) != 0 || st.st_size <= 0) {
                close(fd);
                return false;
            }

            void *mapping = mmap(nullptr, static_cast<size_t>(st.st_size), PROT_READ, MAP_PRIVATE,
                                 fd, 0);
            close(fd);
            if (mapping == MAP_FAILED) {
                return false;
            }

            const auto *base = static_cast<const uint8_t *>(mapping);
            const auto *ehdr = reinterpret_cast<const ElfHeader *>(base);
            const bool valid = st.st_size >= static_cast<off_t>(sizeof(ElfHeader)) &&
                               std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0 &&
                               ehdr->e_shoff != 0 &&
                               ehdr->e_shentsize == sizeof(ElfSection) &&
                               ehdr->e_shnum > 0 &&
                               static_cast<uint64_t>(ehdr->e_shoff) +
                                       static_cast<uint64_t>(ehdr->e_shentsize) *
                                               static_cast<uint64_t>(ehdr->e_shnum) <=
                                       static_cast<uint64_t>(st.st_size);
            if (!valid) {
                munmap(mapping, static_cast<size_t>(st.st_size));
                return false;
            }

            const auto *sections = reinterpret_cast<const ElfSection *>(base + ehdr->e_shoff);
            for (uint16_t index = 0; index < ehdr->e_shnum; ++index) {
                const ElfSection &section = sections[index];
                if (section.sh_type != SHT_DYNSYM && section.sh_type != SHT_SYMTAB) {
                    continue;
                }
                if (section.sh_entsize != sizeof(ElfSymbol) || section.sh_link >= ehdr->e_shnum) {
                    continue;
                }

                const ElfSection &strtab = sections[section.sh_link];
                if (strtab.sh_offset >= static_cast<size_t>(st.st_size) ||
                    strtab.sh_size > static_cast<size_t>(st.st_size) - strtab.sh_offset) {
                    continue;
                }
                if (section.sh_offset >= static_cast<size_t>(st.st_size) ||
                    section.sh_size > static_cast<size_t>(st.st_size) - section.sh_offset) {
                    continue;
                }

                const auto *symbols =
                        reinterpret_cast<const ElfSymbol *>(base + section.sh_offset);
                const size_t symbol_count = section.sh_size / sizeof(ElfSymbol);
                for (size_t symbol_index = 0; symbol_index < symbol_count; ++symbol_index) {
                    const ElfSymbol &symbol = symbols[symbol_index];
                    if (symbol.st_name >= strtab.sh_size ||
                        symbol.st_shndx == SHN_UNDEF ||
                        symbol.st_value == 0) {
                        continue;
                    }

                    const char *name = reinterpret_cast<const char *>(base + strtab.sh_offset +
                                                                      symbol.st_name);
                    const size_t remaining = strtab.sh_size - symbol.st_name;
                    if (std::memchr(name, '\0', remaining) == nullptr) {
                        continue;
                    }
                    if (std::strcmp(name, symbol_name) == 0) {
                        munmap(mapping, static_cast<size_t>(st.st_size));
                        return true;
                    }
                }
            }

            munmap(mapping, static_cast<size_t>(st.st_size));
            return false;
        }

        bool contains_symbol_via_linker(const std::string &path, const char *symbol_name) {
            void *handle = dlopen(path.c_str(), RTLD_NOW | RTLD_NOLOAD);
            if (handle == nullptr) {
                return false;
            }
            void *symbol = dlsym(handle, symbol_name);
            dlclose(handle);
            return symbol != nullptr;
        }

    }  // namespace

    std::vector<std::string> find_loaded_symbol_paths(
            const char *library_name,
            const char *symbol_name
    ) {
        std::vector<std::string> paths;
        if (library_name == nullptr || symbol_name == nullptr) {
            return paths;
        }

        for (const auto &path: find_library_paths(library_name)) {
            if (contains_symbol_in_file(path, symbol_name) ||
                contains_symbol_via_linker(path, symbol_name)) {
                paths.emplace_back(path);
            }
        }
        return paths;
    }

}  // namespace customrom
