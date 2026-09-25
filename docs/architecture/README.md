# Duck Detector module architecture

Duck Detector 使用 ports-and-adapters 边界。Android framework、Binder、KeyStore、JNI 与 native 探测只允许出现在 data 适配器、capability 采集模块和组合根 `:app` 中；证据、报告与扫描契约以及 feature 的 domain 与 presentation 层是纯 JVM 模块，不依赖 Android framework。

## Module dependency direction

```text
:app -> :sdk:<unit> -> :feature:<unit>:<layer> -> :capability:<unit>:<layer> -> :core:<unit>

inside one feature unit:     data -> domain
                             presentation -> domain
                             detector -> data + presentation + domain
                             ui -> detector + presentation + domain
inside one capability unit:  data -> domain

:core:report, :core:scan -> :core:evidence
:core:detector -> :core:evidence + :core:report
:core:ui -> :core:evidence + :core:report + :core:scan
```

Arrows point from a module to the modules it may depend on. Feature units never depend on other feature units, capability units never depend on other capability units, nothing depends on `:app`, pure JVM modules depend neither on Android modules nor on Android artifacts, and only UI modules may use Compose. [`module-boundaries.json`](../../.github/policies/module-boundaries.json) states each layer's rule once as a template and lists only the core modules and `:app` individually. Settings include every module by discovering its directory, so a new unit needs no central entry ([ADR 0001](../adr/0001-gradle-module-boundaries.md), [ADR 0007](../adr/0007-derived-module-classification.md)).

| Module | Responsibility | Forbidden knowledge |
|---|---|---|
| `:core:evidence` | `DetectorId`, `DetectorStatus`, `DetectionSeverity` | Android, reports, scans, UI |
| `:core:native` | Native library handle, payload codec and snapshot collection status shared by every JNI bridge | Android, detector semantics, specific native units |
| `:core:platform` | Android platform access every probe shares: reflection-free failure names, hidden platform failure identity, and the hidden `SystemProperties` and `ServiceManager` access | Detector semantics, verdicts, UI |
| `:core:report` | Typed export model: `DetectorReport`, `DeviceReport`, rows, facts and blocks; `DetectorHeadline`, which every card model states; `DetectorResult` | Android, rendering, specific detectors |
| `:core:scan` | `DetectorSummary`, `ScanSessionRunner` (per-detector scan lifecycle), `ScanCoordinator` (dashboard-wide progress and timing) | Android, UI, specific detectors |
| `:core:detector` | The headless detector contract: `Detector` (identity, scanner, loading report, card model, export), the `DetectorScanner` port and `run`, which returns a `DetectorResult` without any UI | Compose, specific detectors, probes |
| `:core:ui` | Theme, card frames, shared Compose components, typed auto-expansion directive, shared strings, and the `DetectorFeature` / `DetectorSession` and device profile contract the composition root works with | Detector rules, probes, specific detectors |
| `:capability:<unit>:domain` | Evidence types a capability shares with several features | Android, feature interpretation, UI |
| `:capability:<unit>:data` | Collection of shared evidence: package inventory, early preload capture, system property reads, helper processes, SELinux policy carriers, attestation | Feature verdicts, presentation, other capabilities |
| `:feature:<unit>:domain` | The feature's result and report models and pure judgement rules | Android, JNI, UI, other features |
| `:feature:<unit>:data` | Probes, repositories, JNI bridges, platform access and the feature's services | Presentation, UI, other features |
| `:feature:<unit>:presentation` | Card models, report projection (`DetectorReport`) and summary mapping | Android, probes, JNI, other features |
| `:feature:<unit>:detector` | The detector's one headless object, `<Name>Detector`: binds the data scanner, the domain loading report and the presentation mapping and export; used by the SDK and the ui layer | Compose, probes beyond creating the scanner, other features |
| `:feature:<unit>:ui` | Compose card, view model, the `DetectorFeature` implementation and dialogs | Probes, JNI, other features' models |
| `:feature:dashboard:*` | Card ordering, overview, findings and export rendering over `DetectorSession` lists | Any specific detector |
| `:feature:settings:*`, `:feature:update:*`, `:feature:deviceinfo:*` | Supporting features with the same layering | Detector internals |
| `:sdk:runtime` | The headless composition root: `DetectorCatalog`, the one list of detectors in scan-start order; `DuckDetector`, which runs them without any UI; the native libraries; and the process-level hooks a host wires in: `DuckDetectorZygotePreload`, launch evidence capture and the mount-view sampler | Compose, UI modules, per-detector branching |
| `:sdk:aar` | The distributable: fuses `:sdk:runtime` and every headless module it is made of into one AAR with its native libraries and services; `verifySdkAar` fails when a project module is left unfused or a UI library reaches it | Code of its own |
| `:app` | The UI composition root: activities, the dashboard cards of `DetectorFeatures`, notifications, startup policy and package visibility; it names the SDK's zygote preload and calls its launch hooks | Detection rules, probes, report semantics, per-detector branching |

### Capabilities and their consumers

| Capability | Shared evidence | Consumers |
|---|---|---|
| `attestation` | KeyStore attestation collection, extension parsing, trust roots, boot consistency | bootloader, tee |
| `earlypreload` | Mount and virtualization evidence captured by the transparent `NativeActivity` before `MainActivity` | mount, virtualization |
| `helperprocess` | Isolated and helper process services, remote snapshots, dex path and UID identity collectors | mount, nativeroot, virtualization |
| `packageinventory` | Installed package inventory and visibility checks | customrom, dangerousapps, lsposed, nativeroot, virtualization |
| `selinuxpolicy` | SELinux context validity carriers, proc attr and policyload seqno probes, dirty policy preload queries | lsposed, selinux |
| `systemproperties` | Multi-source system property reads and native property snapshots | bootloader, systemproperties |

A capability collects; each consumer interprets. A capability exists only because at least two features consume the same evidence ([ADR 0004](../adr/0004-shared-evidence-capabilities.md)).

## Enforcement

| Guard | Enforces | Self-test |
|---|---|---|
| `DuckDetectorModuleBoundariesPlugin` with `module-boundaries.json` | Classification by layer template or member entry, plugin kind, allowed project dependencies, direction, isolation, JVM purity, UI isolation (Compose only in UI modules) and acyclicity; evaluated while configuring every build | `./gradlew :build-logic:test` |
| `check-native-boundaries.py` with `native-boundaries.json` | Every native file belongs to one unit and lives in the module that owns it, include direction, per-unit CMake targets and their registration, JNI exports owned by the unit's module | `test-native-boundaries.py` |
| `check-jni-contracts.py` | Every Kotlin `external` declaration has exactly one C++ definition with C linkage and `JNIEXPORT`, and vice versa | `test-jni-contracts.py` |
| `check-source-file-length.py` | No source file reaches 600 lines | `test-source-file-length.py` |
| `:sdk:aar:verifySdkAar` | The SDK AAR fuses every project module it needs and reaches no UI library, directly or through an external dependency | Runs on the Fused Library report |
| `DashboardExportGoldenTest` | Export output of every detector stays byte-identical | Golden fixtures in `app/src/test/.../integration/dashboard` |

The CI `contracts` job runs the Python checkers and their self-tests; the `verify` job runs `:build-logic:test`, every module's `unitTest`, `:app:assembleDebug` for all four ABIs and `:app:lintDebug`, which analyses every dependency of `:app`.

## Composition invariants

`DetectorCatalog` in `:sdk:runtime` is the one list of detectors and fixes the order their scans start. `DetectorFeatures` in `:app` names each detector's dashboard card and orders the cards by the catalog; a unit test fails when a detector has no card or a card has no detector. The shell starts one session per card in that order, and the scan coordinator, dashboard and export list the sessions by detector id. Dashboard, export and notification code receive `DetectorSession` lists and typed models. They never enumerate detectors, reflect over detector types, or match presentation text ([ADR 0002](../adr/0002-typed-detector-and-report-contracts.md), [ADR 0008](../adr/0008-headless-detectors-and-sdk.md)).

Scan lifecycle is owned explicitly ([ADR 0003](../adr/0003-scan-lifecycle-ownership.md)):

```text
rescan request -> publish loading state -> wait for the previous scan of the same detector
-> skip if a newer request arrived -> collect -> publish only if still the newest request
```

`ScanSessionRunner` serializes the scans of one detector and suppresses stale results. `ScanCoordinator` observes every published `DetectorSummary` and owns dashboard-wide progress, session identity and timing through a `ScanClock` port.

## Native units

Native code is split into units ([ADR 0005](../adr/0005-native-unit-boundaries.md)). Each unit lives in the module that owns it, as `<module>/src/main/cpp/<unit>/`, with a `CMakeLists.txt` listing its sources, so a detector's C++ sits next to its Kotlin JNI bridge ([ADR 0009](../adr/0009-native-units-in-their-modules.md)). The `DUCKDETECTOR_NATIVE_UNITS` registry in `sdk/runtime/src/main/cpp/CMakeLists.txt` names every unit with its owner, in link order, and links each `duckdetector_<unit>` object library into `libduckdetector.so`. `mount/zygotenext` is the exception: it builds the standalone `libmain.so` that `zygote_next` loads without ART.

| Unit | Owner | May include |
|---|---|---|
| `common` | `:core:native` | - |
| `tee` (including `tee/asm/<abi>`) | `:feature:tee:data` | `common` |
| `virtualization` (including `virtualization/asm/arm64`) | `:capability:helperprocess:data` | `common` |
| `preload` | `:capability:earlypreload:data` | `common`, plus `virtualization/snapshot_builder.h` by recorded exception |
| `selinuxpolicy` | `:capability:selinuxpolicy:data` | `common` |
| `packageinventory`, `systemproperties` | the capability of the same name | `common` |
| `zygotenext` (`mount/zygotenext`) | `:feature:mount:data` | `common` |
| every other directory | `:feature:<directory>:data` | `common` |

## Extension rules

1. Add a detector as `:feature:<name>:{domain,data,presentation,ui}`, implement `DetectorFeature` in its ui layer, and add one entry to `DetectorFeatures`. Settings and the boundary policy pick up the new modules from their directories. Central code must not change.
2. Put judgement rules in the feature's domain layer and keep them pure JVM; the data layer collects and the presentation layer projects.
3. Share evidence acquisition only through a capability used by at least two features. The capability must not interpret the evidence for any of them.
4. Never add a dependency between two feature units or two capability units. If they need the same evidence, extract a capability; if they need the same contract, it belongs in `:core`.
5. Export and dashboard output change only through a feature's own `DetectorReport` projection. Update the golden fixtures deliberately, never to silence a diff.
6. Add native code as `src/main/cpp/<unit>/` in the module that owns it, with a `CMakeLists.txt` that declares its `duckdetector_native_unit` target, one line in the `DUCKDETECTOR_NATIVE_UNITS` registry and a `native-boundaries.json` entry. Cross-unit includes need a header-level exception with a reason.
7. Keep JNI bridges inside the module that owns the native unit. Kotlin `external` functions must be public or private members of a class or object other than a companion object, and must not be overloaded.
8. Keep `:app` a composition root. It may wire adapters and platform entry points but must not acquire detection rules or per-detector branching.
9. Split any file that approaches 600 lines along semantic ownership ([ADR 0006](../adr/0006-source-file-length-limit.md)); there is no baseline to hide in.
10. Record every deliberate boundary exception in [follow-ups](./follow-ups.md) or an ADR, together with the reason it is still needed.
