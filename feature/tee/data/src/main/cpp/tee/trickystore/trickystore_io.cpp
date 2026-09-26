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

#include "tee/trickystore/trickystore_internal.h"

#include "tee/common/syscall_facade.h"

#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <vector>

namespace ducktee::trickystore::detail {

    int raw_open(const char *path, int flags) {
#if defined(__NR_openat)
        return static_cast<int>(syscall(__NR_openat, AT_FDCWD, path, flags, 0));
#else
        return open(path, flags);
#endif
    }

    int open_binder_device() {
        int fd = raw_open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            fd = raw_open("/dev/vndbinder", O_RDWR | O_CLOEXEC);
        }
        return fd;
    }

    std::vector<ducktee::common::SyscallBackend> available_backends() {
        std::vector<ducktee::common::SyscallBackend> backends;
        for (const auto backend: kIoctlBackends) {
            if (ducktee::common::backend_available(backend)) {
                backends.push_back(backend);
            }
        }
        return backends;
    }

    std::vector<ducktee::common::SyscallBackend> rotated_available_backends(const int attempt) {
        auto backends = available_backends();
        if (backends.empty()) {
            return backends;
        }
        const auto rotation = static_cast<std::size_t>(attempt) % backends.size();
        std::rotate(backends.begin(), backends.begin() + rotation, backends.end());
        return backends;
    }

}  // namespace ducktee::trickystore::detail
