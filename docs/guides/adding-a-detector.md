# Adding a detector

A detector lives entirely in `feature/<name>/`, as five small Gradle modules, one per layer. Outside that directory it is named in exactly one place, its entry in `DetectorCatalog`, which fixes the order scans start. Everything else finds the new modules from their directory, including the Gradle settings, the boundary policy, both composition roots, the app's list of dashboard cards, the SDK AAR, the dashboard and the export.

## 1. Research before you generate anything

[AGENTS.md](../../AGENTS.md) applies in full. Before writing a probe, establish:

- the question the detector answers, and the subsystem that produces the signal it observes;
- the authoritative source for that behaviour, such as Android documentation, AOSP, the applicable Android kernel or the architecture manual, and the Android, kernel and ABI versions it holds for;
- what an app process can and cannot see through SELinux, namespaces, package visibility and permissions, and the result states that follow: observed, not observed, unavailable, unsupported or failed;
- how a legitimate device could produce the signal, and how a modified one could hide it.

Condense the first two points into one sentence. It becomes `--description` and opens the detector's documentation.

Record the research in `feature/<name>/EVIDENCE.md`, which the scaffold writes as a draft. Give each signal family one entry with the AGENTS.md §12 chain: observable signal, producing subsystem, mechanism, references, applicability, visibility limits, result states and interpretation. Cite the sources you actually read, Tier 1 where one exists. When a signal rests only on a tool's observed behaviour or on a source you have not reviewed, start its references with `Discovery only:` so that readers can see it. Set `Status: reviewed` when the record is complete; `check-evidence-records.py` rejects a draft, a missing field and references that name no source.

## 2. Generate the detector

```bash
python3 scripts/new_detector.py debugger \
    --description "looks for a tracer attached to the app process through TracerPid in /proc/self/status"
```

| Option | Default | Meaning |
|---|---|---|
| `NAME` | required | Directory and package segment: lowercase letters and digits |
| `--description` | required | What the detector looks for and why that is evidence |
| `--class-name` | `NAME` capitalised | Class name prefix, such as `PlayIntegrityFix` for `playintegrityfix` |
| `--id` | the class name in snake_case | Stable id in results and exports |
| `--title` | the class name split into words | Card and report title |
| `--native` | off | Adds a native unit with its JNI bridge |

The script creates:

```text
feature/debugger/
├─ domain/        DebuggerReport, DebuggerReportStatus (the verdict) and its tests
├─ data/          DebuggerRepository (the probe); with --native, the JNI bridge and src/main/cpp/debugger/
├─ presentation/  DebuggerCardModel, DebuggerCardModelMapper, the DetectorReport export and their tests
├─ detector/      DebuggerDetector, which binds the layers for the SDK and the app
└─ ui/            DebuggerDetectorCard and DebuggerDetectorFeature
```

It adds `DebuggerDetector` to `DetectorCatalog`, after bootloader and TEE and ordered by id. The ui layer exports the card as `detectorFeature`, the name from which the app generates its list of cards. With `--native` it also registers the unit in `DUCKDETECTOR_NATIVE_UNITS` and `native-boundaries.json`. Before writing anything, it rejects an existing directory, class, id or native unit.

The generated detector builds and passes every guard. Until its probe observes the device, it reports **Not evaluated** with an informational status, so an unfinished detector never reads as a clean result.

## 3. Fill in the layers

| Layer | What you write | Rules |
|---|---|---|
| `domain` (pure JVM) | The observations in `<Name>Report` and the verdict in `<Name>ReportStatus.kt`, with tests for every branch | No Android. Every judgement rule lives here, and a report with `probed = false` stays informational |
| `data` (Android) | The probe in `<Name>Repository.collect()`. Set `probed = true` only when a probe actually observed the device, and state `unavailableReason` when it could not. An exception becomes a FAILED report named by `FailureName` | Collect; do not judge. Evidence another detector also needs comes from a capability |
| `data`, native unit | `collect_snapshot()` in `src/main/cpp/<name>/native_bridge.cpp`. Emit `AVAILABLE=1` only when the probe observed the device, and escape every value with `escape_payload_value` | The unit may include only `common/`. List new sources in the unit's `CMakeLists.txt` |
| `presentation` (pure JVM) | The card's words and rows in `<Name>CardModelMapper`, and its export blocks in `<Name>DetectorReport.kt` | Project the domain verdict; never decide it again |
| `detector` | Usually nothing | No Compose |
| `ui` | Sections of `<Name>DetectorCard`, built from the `:core:ui` card components | No probes and no rules |

State what was observed and what it implies, never that a device is secure or compromised (AGENTS.md §19). Build user-facing text in the mapper from typed values. Do not assemble text in the data layer, and never derive wording from class names.

Decide from typed values too. When the card or the export has to choose a row, an icon or a status, carry an enum, id or flag from where the evidence is produced, and let enums own their labels. Never compare, search or strip the words another layer wrote; `check-text-protocols.py` rejects it.

### When the detector needs the process or the user

Declare the need on the detector; both composition roots apply it without naming the detector.

| Need | Declare it in | Applied by |
|---|---|---|
| Work in the app zygote, before any isolated process forks | `appZygotePreload` on the `Detector` | `DuckDetectorZygotePreload`, which the SDK's manifest names |
| A decision only the user can make | `consents` on the `Detector`, with the prompt and setting in the ui module's `consentCards` | The app's startup policy screen and settings; an SDK host reads and records them itself |
| A service, an intent filter or a package query | The data module's `AndroidManifest.xml`, on the component that uses it | The manifest merger, for the app and every SDK host |

## 4. Verify

```bash
./gradlew :feature:<name>:domain:test :feature:<name>:presentation:test   # the fast loop
./gradlew unitTest :app:assembleDebug buildHealth                       # before a pull request
python3 .github/scripts/check-detector-touch-points.py
```

Also run `check-evidence-records.py` and `check-text-protocols.py`. With a native unit, run `check-jni-contracts.py` and `check-native-boundaries.py` as well. When `buildHealth` fails, its report names the exact dependency to add, remove or change between `api` and `implementation`.

JVM tests prove the rules, not the probe. Validate the probe on clean, modified and unsupported devices, as AGENTS.md §23 requires.

## What you do not touch

| File | Why not |
|---|---|
| `settings.gradle.kts` | Modules are included from their directories |
| `module-boundaries.json` | Every layer is classified by its path |
| `app/build.gradle.kts`, `sdk/runtime/build.gradle.kts`, `sdk/aar` | The ui and detector layers are discovered, and the AAR fuses every headless module |
| `DetectorFeatures` in the app | Its cards come from `detectorCards`, which the build generates from every ui module's `detectorFeature` |
| The app's manifest, startup screen and settings | Components come from module manifests, and consents are shown from `consentCards` |
| Dashboard, export and notification code | They work on sessions and `DetectorReport` values, never on a specific detector |
| The golden export | It covers the detectors recorded in `golden-detectors.txt`, so a new detector does not have to join it |

To add a detector to the golden export, run `DD_UPDATE_GOLDEN=1 ./gradlew :app:testDebugUnitTest --tests '*DashboardExportGoldenTest*'` and review the diff.

## Changing a detector

The change stays inside `feature/<name>/`, and a changed signal changes its entry in `EVIDENCE.md` in the same commit. If the detector is recorded in the golden export and its card or export changes, regenerate the golden report as above. Each detector draws its fixtures from its own sequence, so the diff touches only that detector's section and the overview lines.

## Sharing evidence

When a second detector needs the same evidence, move its collection into a capability, `capability/<unit>/{domain,data}`. The capability collects, and each detector interprets ([architecture overview](../architecture/README.md#capabilities-and-their-consumers)). A feature never depends on another feature.

## Removing a detector

Delete `feature/<name>/` and its line in `DetectorCatalog`. For a native unit, also delete its `DUCKDETECTOR_NATIVE_UNITS` line and its `native-boundaries.json` entry. If the detector was recorded in the golden export, regenerate it.
