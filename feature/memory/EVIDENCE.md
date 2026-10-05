# Memory evidence record

Status: reviewed

The Memory detector asks whether this process's own code and mappings show signs of in-process hooking or injected code. Findings describe this process only.

## Signals

### Symbol resolution and entry prologues

- Observable signal: where dlsym resolves sensitive libc and linker symbols, and the first bytes at those entry points.
- Producing subsystem: the dynamic linker and the mapped libc and linker images in this process.
- Mechanism: a PLT or GOT hook resolves the symbol outside its module; an inline hook replaces the prologue with a branch or a load-and-branch trampoline.
- References: kernel/common Documentation/filesystems/proc.rst for /proc/self/maps; bionic linker/linker_namespaces.h for the loader's namespaces. Discovery only for the prologue byte patterns, which are the probe's instruction heuristics.
- Applicability: resolution checks on every ABI; entry byte checks only on arm64 and x86_64.
- Visibility limits: dlopen(nullptr) can fail; other ABIs report the entry check as unsupported.
- Result states: mismatch, hook-like, jump entry, clean, unavailable, unsupported ABI.
- Interpretation: an escaped symbol or branch prologue is danger; a trampoline-style entry alone is review.

### Mappings, file-backed code and loader visibility

- Observable signal: writable or anonymous executable mappings, shared-dirty or privately copied executable system pages, swapped executable pages, executable memfd, ashmem, deleted libraries or /dev/zero, modules visible to maps but not to dl_iterate_phdr, and a remapped or unusually based [vdso].
- Producing subsystem: the kernel's view of this process's address space.
- Mechanism: injected code usually needs anonymous or writable executable memory or hides its loader entry, and code patched in place turns each page it writes into a private copy.
- References: kernel/common Documentation/filesystems/proc.rst (maps and smaps fields such as Private_Dirty, Swap and Anonymous, which in a MAP_PRIVATE file mapping counts the pages replaced by private copies, and the [vdso] mapping); kernel/common ASB-2021-05-05_4.19-stable fs/proc/task_mmu.c and mm/gup.c (seq_print_vma_name pins the page holding each anonymous VMA name with get_user_pages_remote, and should_force_cow_break, the CVE-2020-29374 workaround, turns every pinning lookup on a MAP_PRIVATE mapping into a write fault, which copies a file page); chromium build/config/compiler/BUILD.gn and partition_alloc page_allocator_internals_posix.cc (Android builds link with --no-rosegment, which keeps .rodata in the executable segment, and PartitionAlloc names its anonymous mappings with .rodata literals); bionic linker/linker_phdr.cpp, linker/linker.cpp and linker/linker_relocate.cpp (the loader maps load segments with their final protection and makes executable ones writable only for text relocations, which it refuses in 64-bit processes and in 32-bit apps targeting API 23 or later); kernel/common arch/arm64/kernel/vdso.c and arch/arm64/include/asm/elf.h (AArch64 processes always get a vDSO and AT_SYSINFO_EHDR, 32-bit processes only with CONFIG_COMPAT_VDSO); bionic libc/bionic/vdso.cpp (no AT_SYSINFO_EHDR means no vDSO).
- Applicability: every ABI and release; the [vdso] checks need a vDSO, which the kernel does not map for 32-bit processes on arm64 kernels without CONFIG_COMPAT_VDSO, on arm kernels without CONFIG_VDSO, or on x86 kernels with it disabled.
- Visibility limits: ART's JIT legitimately creates anonymous executable code; the repository removes that known case. smaps shows that a page of a system mapping was replaced by a private copy, not why or whether its bytes still differ from the file. A write makes such a copy. So does any read that pins the page on kernels with the forced COW break, which ACK carries in 4.19-stable and android11-5.4 but not at the heads of android12-5.4, android12-5.10 or android13-5.10; ACK branches before android13-5.10 also pin the page holding each anonymous VMA name whenever maps or smaps is printed, this detector's own reads included. Chromium keeps those names in .rodata inside its executable segment, so on kernels with both behaviours the WebView library's executable mapping shows a copy in any process that loads it. Outside arm64, a process with neither AT_SYSINFO_EHDR nor a [vdso] mapping is taken as one the kernel gave no vDSO, so code that removes both goes unnoticed there.
- Result states: anomaly, review, clean; the [vdso] checks also report when the kernel mapped no vDSO.
- Interpretation: writable executable code, anonymous executable mappings outside ART and shared-dirty system code are danger; swapped executable pages and privately copied system code are review. The app maps the WebView library into this process for its mount-view sampler, so this row sees both a tool that patches WebView in every process and the read-triggered copies above.

### Signal handlers

- Observable signal: the handlers installed for SIGTRAP, SIGBUS, SIGSEGV and SIGILL.
- Producing subsystem: the kernel's per-process signal actions.
- Mechanism: hooking and instrumentation frameworks install handlers that point into anonymous memory.
- References: Discovery only: the handler heuristics follow observed Frida and hook framework behaviour.
- Applicability: every ABI.
- Visibility limits: legitimate crash reporters install handlers too, which is why only suspicious targets count.
- Result states: detected, review, clean.
- Interpretation: handlers in anonymous or loader-suspicious memory are review or danger by target.
