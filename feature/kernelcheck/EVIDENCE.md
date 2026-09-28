# Kernel Check evidence record

Status: reviewed

The Kernel Check detector asks whether the running kernel looks like a custom or community kernel rather than the vendor's build, and whether kernel-facing views agree. These are heuristics about the build; they do not prove root.

## Signals

### Kernel identity consistency

- Observable signal: the kernel release and version from the uname syscall, `uname`, /proc/version, /proc/sys/kernel/osrelease and System.getProperty.
- Producing subsystem: the kernel's UTS namespace and procfs.
- Mechanism: a module that hooks one identity path leaves the others disagreeing.
- References: kernel/common Documentation/filesystems/proc.rst (/proc/version and /proc/sys/kernel); system/core rootdir/init.rc (`hostname localhost`, so uname output starts "Linux localhost").
- Applicability: every release.
- Visibility limits: none for these world-readable views.
- Result states: consistent, mismatch.
- Interpretation: a mismatch between identity sources is evidence of rewriting.

### Community kernel markers

- Observable signal: emoji, CJK and other scripts, Telegram handles, @ mentions, known community identifiers and non-release major versions in the kernel identity.
- Producing subsystem: the kernel build's version string.
- Mechanism: community kernels usually brand their version strings.
- References: Discovery only: the marker catalog comes from observed community kernel strings.
- Applicability: every release.
- Visibility limits: a custom kernel can use a vendor-looking string.
- Result states: detected, clean.
- Interpretation: markers are heuristics and stay below direct evidence.

### Boot command line and kernel pointers

- Observable signal: critical options in /proc/cmdline and whether kernel pointers are exposed.
- Producing subsystem: the bootloader's command line and the kernel's kptr_restrict setting.
- Mechanism: permissive or debug options and exposed pointers are unusual on user builds.
- References: kernel/common Documentation/filesystems/proc.rst (/proc/cmdline and /proc/kallsyms).
- Applicability: /proc/cmdline is readable only where SELinux allows it.
- Visibility limits: unreadable sources are reported as partial.
- Result states: detected, clean, unavailable.
- Interpretation: a permissive command line is danger; pointer exposure is a warning.

### Storage path filter bypass

- Observable signal: whether /sdcard/Android/data can be listed through a path with ignorable Unicode codepoints.
- Producing subsystem: MediaProvider's FUSE path handling for shared storage.
- Mechanism: an unpatched path filter treats a path with an ignorable codepoint as a different, unprotected directory.
- References: Discovery only: the report labels this CVE-2024-43093 after the Android security bulletin; the MediaProvider fix itself was not reviewed.
- Applicability: devices before the fix.
- Visibility limits: storage permissions and scoped storage change what the probe can list.
- Result states: unpatched, partially patched, patched, inconclusive.
- Interpretation: a working bypass is a patch-level finding, not a kernel finding.

### ARM64 CPU identity

- Observable signal: MIDR_EL1 read through the kernel's EL0 MRS emulation on each logical CPU, against the identity the kernel cached for that CPU in its sysfs midr_el1 node or its /proc/cpuinfo block.
- Producing subsystem: the kernel's per-CPU cpuinfo_arm64 record and its MRS emulation.
- Mechanism: a read pinned to a CPU, and confirmed by getcpu() to have run there, exposes a cached identity that was rewritten. Pinning alone is not enough: moving the app to another cpuset or pausing a CPU moves the thread, and a read taken on another core of a heterogeneous SoC would disagree for that reason alone, so such reads are discarded and a value counts only when three confirmed reads agree.
- References: kernel/common Documentation/arch/arm64/cpu-feature-registers.rst (MIDR_EL1 holds the value of the CPU it is fetched on, racy without affinity) and arch/arm64/kernel/cpufeature.c on android13-5.15 and android15-6.6 (the emulated value is read_cpuid_id()); kernel.org v6.12 arch/arm64/kernel/cpuinfo.c (sysfs midr_el1 and /proc/cpuinfo both print cpu_data[cpu].reg_midr, stored when the CPU comes online); kernel.org v5.10 and v6.12 arch/arm64/kernel/entry-common.c (the emulation runs with interrupts enabled); kernel.org v5.10 to v6.12 kernel/cgroup/cpuset.c (cpuset_attach() resets the affinity of moved tasks; 6.6 and 6.12 keep a requested mask only where it intersects the new cpuset, 6.1 does not) and kernel/sched/core.c (select_fallback_rq() moves pinned tasks off inactive CPUs); kernel.org v6.1 kernel/sys.c (getcpu() reports the CPU it runs on); kernel.org v6.12 and v6.15 arch/arm64/include/asm/el2_setup.h and arch/arm64/kvm/hyp/include/hyp/sysreg-sr.h (what a KVM guest reads as MIDR_EL1); system/core libprocessgroup task_profiles.cpp and task_profiles.json (app threads join the top-app, foreground and background cpusets); bionic libc/SYSCALLS.TXT (bionic calls getcpu, so app seccomp allows it); the Arm Architecture Reference Manual defines the register but was not consulted here.
- Applicability: arm64 only; other ABIs report it as unavailable.
- Visibility limits: kernels without the register exposure cannot be compared, and CPUs outside the app's cpuset are not visited. KVM gives a guest the MIDR_EL1 of the physical CPU its vCPU is running on unless the VMM sets the guest's implementation ID registers, which Linux 6.15 allows and 6.12 does not, so a guest on a heterogeneous host can disagree with its own cached identity without any rewriting.
- Result states: consistent, mismatch, partial, unavailable.
- Interpretation: a confirmed mismatch is danger. CPUs whose reads could not be confirmed on the pinned CPU, or changed between reads, are not compared and leave the result partial.

## Known gaps

- The storage path filter bypass is a MediaProvider patch check that lives in the kernel detector; see docs/architecture/follow-ups.md.
