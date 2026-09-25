# Architecture follow-ups

These are known, deliberate gaps left by the module refactor. Each one was kept because fixing it would change detector semantics, shipped binaries or component identity, which the refactor was not allowed to do. Remove an entry in the same change that resolves it.

## Text protocols inside features

Some features still branch on method labels that their own data layer produces. For example, `KernelCheckMethods.kt` in `:feature:kernelcheck:data` emits the label `"cvePatchCheck"`, and `KernelCheckCardStatus.kt` and `KernelCheckCardRows.kt` in `:feature:kernelcheck:presentation` compare against it. The protocol never crosses a feature boundary, but renaming the label silently changes the card. Replace such labels with typed method or reason identifiers in each feature's domain layer, one feature per change, with the card and export golden tests proving the output is unchanged.

## Early virtualization preload matches finding labels

`preload/virtualization_early_detector.cpp` derives its early flags by comparing the finding labels and groups produced by `virtualization::collect_snapshot`, such as `"ro.kernel.qemu"`, `"Emulator device node"` and `"TRANSLATION"`. This is the reason for the one include exception in `native-boundaries.json`. The include itself is legitimate, because both captures must come from one probe implementation, but the label matching is a text protocol between two native units. Give `virtualization::SnapshotFinding` a typed kind and match on it.

## Historical names in the helper process capability

`:capability:helperprocess:data` still uses the class names it had inside the virtualization feature, for example `VirtualizationProbeService`, `VirtualizationIsolatedProbeService`, `VirtualizationProbeManager` and `VirtualizationNativeBridge`. Renaming them changes manifest component names and JNI symbols, so it must be one deliberate change that also updates the merged manifest reference and the native bindings.

## Release native builds never use the Release configuration

Release variants build the native libraries with CMake's `RelWithDebInfo` configuration because nothing selects `Release`. The `$<CONFIG:Release>` flags in `sdk/runtime/src/main/cpp/CMakeLists.txt` therefore never reach shipped builds. These flags are `-ffunction-sections`, `-fdata-sections`, hidden visibility, `INTERPROCEDURAL_OPTIMIZATION_RELEASE` and `-Wl,--gc-sections`. The shipped `libduckdetector.so` is compiled with `-O2 -g` and default visibility; only `libmain.so` always hides its symbols. The refactor kept this behavior and verified it unchanged. Enabling the flags changes shipped binaries and the code layout of timing-sensitive probes, so it needs on-device validation of the timing and trap probes before it lands.

## Lint translation completeness is module-scoped

Lint's `MissingTranslation` check compares a string only against the locales present in the module that declares it. `mount_diagnostic_clipboard_label`, `native_root_diagnostic_clipboard_label` and `tee_diagnostic_clipboard_label` moved from `:app` into feature modules. Those modules have fewer locale folders, so their missing translations are no longer reported, although the strings themselves are unchanged. Add the missing translations, or add a repository-wide translation completeness check that does not depend on module layout.

## Shared per-scan platform snapshots

Each detector still collects its own platform evidence during its scan, even when several detectors read the same source, such as the package inventory or system properties. A scan session that captures such evidence once and hands the same snapshot to every consumer would make cross-detector correlation exact, but it changes probe timing and ordering, so it needs its own design and on-device validation.

## Startup policy wires the TEE network consent

The startup policy screens and app shell in `:app` read and write `TeeNetworkConsentStore` and `TeeNetworkPrefs` from `:feature:tee:data`. This lets the user consent to downloading Google's revocation feed before the first scan. It is composition-root wiring rather than a detection rule, but it is the only place outside `DetectorFeatures` where the shell names a detector. If another feature needs startup consent, replace it with a typed consent contract in `:core`.

## Composable detector sessions

`DetectorSession.Card()` is `@Composable`, which makes `:core:detector` an Android library. The scan and report contracts it builds on are pure JVM, so a JVM-only session contract with a separate UI binding would allow composition-level tests without Robolectric or instrumentation. This only matters if such tests become necessary.
