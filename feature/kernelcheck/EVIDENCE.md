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

- Observable signal: MIDR_EL1 values read through the kernel against the CPU the device reports.
- Producing subsystem: the kernel's exposure of MIDR_EL1 to user space.
- Mechanism: a pinned MIDR comparison exposes CPU identity rewriting.
- References: kernel/common Documentation/arch/arm64/cpu-feature-registers.rst (MIDR_EL1 is exposed to user space); the Arm Architecture Reference Manual defines the register but was not consulted here.
- Applicability: arm64 only; other ABIs report it as unavailable.
- Visibility limits: kernels without the register exposure cannot be compared.
- Result states: consistent, mismatch, unavailable.
- Interpretation: a mismatch is a warning.

## Known gaps

- The storage path filter bypass is a MediaProvider patch check that lives in the kernel detector; see docs/architecture/follow-ups.md.
