# Zygisk evidence record

Status: reviewed

The Zygisk detector asks whether code injected through zygote (Zygisk, Zygisk Next, ReZygisk, NeoZygisk) left traces in this app process. Strong traces point at injection; heuristic traces need corroboration.

## Signals

### Linker and namespace integrity

- Observable signal: whether dlopen, dlsym and dlclose resolve into the loader image, whether their entries branch straight out of it, and whether restricted-path libraries are loaded.
- Producing subsystem: the dynamic linker and this process's linker namespaces.
- Mechanism: injection frameworks hook the loader's entry points or load libraries from paths the app's namespace should not reach.
- References: bionic linker/linker_namespaces.h (is_accessible and isolated namespaces); kernel/common Documentation/filesystems/proc.rst for /proc/self/maps. Discovery only for the restricted path list.
- Applicability: the owning-image check on every ABI; the branch decoding on arm64 only.
- Visibility limits: an unreadable /proc/self/maps leaves the snapshot unavailable.
- Result states: bypassed, clean, unavailable.
- Interpretation: a linker hook or namespace bypass is a strong hit and danger.

### Memory map families

- Observable signal: suspicious executable mappings, deleted loaders, JIT cache drift, dirty system library pages, solist drift, atexit routing and heap entropy.
- Producing subsystem: this process's address space and the linker's soinfo list.
- Mechanism: an injected library that later unloads or hides still leaves mapping, dirty page or allocator residue.
- References: kernel/common Documentation/filesystems/proc.rst (maps and smaps fields). Discovery only for the per-framework residue patterns.
- Applicability: every ABI; heap entropy only where jemalloc state is readable.
- Visibility limits: each family is a heuristic with known benign causes.
- Result states: strong hit, heuristic hit, clean, unavailable.
- Interpretation: one heuristic family is a warning; two distinct families are danger, because they observe different artifacts of the same injection.

### Threads, descriptors and FD trap

- Observable signal: TracerPid, thread names, open descriptor targets, and whether a descriptor planted before fork is closed by an injection stack.
- Producing subsystem: procfs and zygote's fork path.
- Mechanism: Zygisk closes or reopens descriptors around specialization, and tracing tools set TracerPid.
- References: kernel/common Documentation/filesystems/proc.rst (status TracerPid, fd); frameworks/base core/jni/com_android_internal_os_Zygote.cpp for the specialization path. Discovery only for the FD trap's Zygisk-specific expectation.
- Applicability: the FD trap is skipped under a debugger or profiling agent.
- Visibility limits: debuggers and agents legitimately change descriptors and TracerPid.
- Result states: FD trap hit, heuristic hit, clean, skipped.
- Interpretation: an FD trap hit is danger; thread and descriptor names are heuristics.
