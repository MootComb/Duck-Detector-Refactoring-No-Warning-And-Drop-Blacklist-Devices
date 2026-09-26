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

#ifndef DUCKDETECTOR_NATIVEROOT_PROBES_KERNELPATCH_SUPERCALL_ABI_H
#define DUCKDETECTOR_NATIVEROOT_PROBES_KERNELPATCH_SUPERCALL_ABI_H

namespace duckdetector::nativeroot {

    // KernelPatch patches arm64 kernels only and takes over syscall 45 of the
    // arm64 table. Other ABIs, including 32-bit processes on an arm64 kernel,
    // use their own syscall numbering, so a probe built for them never reaches it.
    inline constexpr const char *kKernelPatchArm64Only =
            "Not run: KernelPatch's supercall is syscall 45 of the arm64 table, which this ABI does not call.";

}  // namespace duckdetector::nativeroot

#endif  // DUCKDETECTOR_NATIVEROOT_PROBES_KERNELPATCH_SUPERCALL_ABI_H
