# Architecture follow-ups

These are known, deliberate gaps left by the module refactor. Each one was kept because fixing it would change detector semantics, shipped binaries or component identity, which the refactor was not allowed to do. Remove an entry in the same change that resolves it.

## Text that data layers still read

`check-text-protocols.py` covers presentation, ui, core, SDK, app and native code, but not data layers, which interpret the platform's text by nature. Some of what they read is DuckDetector's own. The Mount repository filters the early preload capability's findings by splitting their `type|message` strings, although the capability has a typed accessor for the messages. The Native Root cgroup probe compares its own rule labels. The SELinux attr/current results carry their outcome as string constants the capability defines. Each stays inside the unit that wrote or received the text; typing them would let the checker cover data layers too.

## SELinux note statuses

The SELinux card's policy and audit notes are typed, but each kind keeps the status the old keyword search gave its text, including three that look wrong. "No permissive domains detected" is a warning, because its text contains "permissive". "Security classes look complete" is informational, because its text contains none of the searched words. And the note for audit probes that exposed tampering is informational for the same reason, although its state is the strongest audit finding. Correcting them changes what the card shows, so each needs a deliberate decision.

## SELinux context validity merges two failures

The context validity oracle is untrusted either because its controls failed or because its repeated writes disagreed, and the repository reports both as one self-test failure. The card has separate verdicts for the two ("untrusted" and "unstable context oracle"), but its reading sets `repeatabilityFailed` for every self-test failure, as the old text match on "repeatability failed" did. The probe result keeps `oracleControlsPassed` and `ksuResultsStable`, so the reading could tell the causes apart. Doing so changes the card's and the export's verdict for devices whose controls fail, so it needs a deliberate change.

## Release native builds never use the Release configuration

Release variants build the native libraries with CMake's `RelWithDebInfo` configuration because nothing selects `Release`. The `$<CONFIG:Release>` flags in `sdk/runtime/src/main/cpp/CMakeLists.txt` therefore never reach shipped builds. These flags are `-ffunction-sections`, `-fdata-sections`, hidden visibility, `INTERPROCEDURAL_OPTIMIZATION_RELEASE` and `-Wl,--gc-sections`. The shipped `libduckdetector.so` is compiled with `-O2 -g` and default visibility; only `libmain.so` always hides its symbols. The refactor kept this behavior and verified it unchanged. Enabling the flags changes shipped binaries and the code layout of timing-sensitive probes, so it needs on-device validation of the timing and trap probes before it lands.

## Lint translation completeness is module-scoped

Lint's `MissingTranslation` check compares a string only against the locales present in the module that declares it. `mount_diagnostic_clipboard_label` and `native_root_diagnostic_clipboard_label` moved from `:app` into feature modules. Those modules have fewer locale folders, so their missing translations are no longer reported, although the strings themselves are unchanged. `feature/tee/ui` has every locale since it took over TEE's consent strings, so lint reports `tee_diagnostic_clipboard_label`'s missing translations again. Add the missing translations, or add a repository-wide translation completeness check that does not depend on module layout.

## Shared per-scan platform snapshots

Each detector still collects its own platform evidence during its scan, even when several detectors read the same source, such as the package inventory or system properties. A scan session that captures such evidence once and hands the same snapshot to every consumer would make cross-detector correlation exact, but it changes probe timing and ordering, so it needs its own design and on-device validation.

## Public API dumps come from javap

`DuckDetectorPublicApiPlugin` records the SDK contract modules' public API with javap, because Kotlin's ABI validation fails on libraries built with AGP's built-in Kotlin: its dump task has no class files to read. javap cannot tell Kotlin `internal` declarations from public ones, which is safe only while the contract modules declare nothing internal. When Kotlin's ABI validation supports these libraries, switch to it and regenerate the dumps in one change.

## Early launch capture starts a fixed activity

The transparent `NativeActivity` in the `preload` unit starts `<applicationId>.MainActivity` by name after its capture. An SDK host whose launch activity has another name cannot reuse the launcher, so its Mount and Virtualization detectors report the early capture as unavailable. Reading the target activity from a `<meta-data>` entry on the `NativeActivity` would lift this; the app's behaviour must stay identical.

## TEE probes that classify keystore errors by message

Two TEE deep checks still read platform error text. The oversized challenge probe counts any exception as a rejection, so a busy or failing keystore reads as the expected answer. The update subcomponent probe recognises a key-not-found style failure by matching "KEY_NOT_FOUND" or "error 7" in the exception message. On Android 13 and later, `android.security.KeyStoreException.getNumericErrorCode()` gives the typed code. Classify by it where it exists, and report the probe as not completed otherwise.

## The storage path filter check lives in Kernel Check

`KernelCvePatchProbe` tests whether `/sdcard/Android/data` can be listed through paths with ignorable Unicode codepoints, which is MediaProvider's path handling rather than a kernel property, and the report calls it CVE-2024-43093 without a reviewed fix reference. Move it next to the Dangerous Apps directory listing methods that use the same bypass, or into a storage detector, and cite the fix. The move changes a card and the export, so it needs its own change with a golden update.

## Discovery-only evidence

Eleven evidence record entries start with "Discovery only:" because they rest on a tool's observed behaviour or on a source this review did not read. They are the KernelSU interfaces, the kernel token catalogs, TrickyStore's in-process signatures, the TEE timing skip signatures, SOTER, LSPosed's class and log names, Zygisk's residue patterns, the Memory prologue and handler heuristics, and the vendor-specific bootloader and Widevine behaviour. Review each tool's source, or the vendor documentation, and replace the marker with the reference, or lower the signal's confidence where the source does not support it.

## "Clean" rows that mean "not observed"

Most method rows say "Clean" when a probe ran and saw nothing, and several say "Normal". AGENTS.md section 19 prefers "not observed", which does not suggest the device was proven clean. Changing the word changes every card and the golden export, so it needs one cross-detector copy change rather than piecemeal edits.

## SOTER environment check swallows inspector failures

`SoterCapabilityProbe` wraps the environment inspector in `runCatching` and falls back to an empty snapshot. `BiometricManager.canAuthenticate` needs `USE_BIOMETRIC`, so a host without it gets an "abnormal environment" result of false instead of "not evaluated". Carry the inspector's failure into `TeeSoterState` and show the environment check as unavailable.

## Device validation of the evidence review

The evidence review changed what several probes report. These changes were verified with JVM tests and native builds for all four ABIs, not on devices:

- the netlink boundary's applicability by release and target SDK;
- the SUSFS outcome codes;
- the paths now reported as not observable in Native Root, SU and SELinux;
- the TEE deep checks that now read "Did not complete";
- the gate on app attestation keys;
- the operation error path grading;
- the KernelPatch latency availability.

Validate them on a stock device, a rooted device with /data/adb present, an SDK host with an old target SDK, and a non-arm64 device before relying on the new states in a release.

