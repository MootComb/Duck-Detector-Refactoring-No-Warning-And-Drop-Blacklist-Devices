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

- Observable signal: writable or anonymous executable mappings, dirty or swapped executable system pages, executable memfd, ashmem, deleted libraries or /dev/zero, and modules visible to maps but not to dl_iterate_phdr.
- Producing subsystem: the kernel's view of this process's address space.
- Mechanism: injected code usually needs anonymous or writable executable memory or hides its loader entry.
- References: kernel/common Documentation/filesystems/proc.rst (maps and smaps fields such as Private_Dirty and Swap).
- Applicability: every ABI and release.
- Visibility limits: ART's JIT legitimately creates anonymous executable code; the repository removes that known case.
- Result states: anomaly, review, clean.
- Interpretation: writable or anonymous executable code outside ART is danger; swapped executable pages are review.

### Signal handlers

- Observable signal: the handlers installed for SIGTRAP, SIGBUS, SIGSEGV and SIGILL.
- Producing subsystem: the kernel's per-process signal actions.
- Mechanism: hooking and instrumentation frameworks install handlers that point into anonymous memory.
- References: Discovery only: the handler heuristics follow observed Frida and hook framework behaviour.
- Applicability: every ABI.
- Visibility limits: legitimate crash reporters install handlers too, which is why only suspicious targets count.
- Result states: detected, review, clean.
- Interpretation: handlers in anonymous or loader-suspicious memory are review or danger by target.
