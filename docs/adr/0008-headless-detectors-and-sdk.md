# ADR 0008: Headless detectors, one SDK library and one registration per detector

- Status: Accepted; decision 8 amended by [ADR 0011](./0011-generated-dashboard-cards.md)
- Date: 2026-09-25

## Context

Detection could only run inside the application:

- `:app` built the native libraries, so no library module could ship them.
- `DetectorFeatures` in `:app` bound each Compose feature to its data repository. Scanning therefore required UI code.
- `:app` also held detection hooks: the app zygote preload composition, the capture of early launch evidence, and the hidden `WebView` whose renderer process the isolated mount-view scanner compares against.
- `:core:detector`, the contract every detector implemented, was a Compose module.

Fourteen of the fifteen detectors carried the same UI plumbing, differing only in type names: about 100 lines of view model, 70 of session and 60 of UI state and summary mapping. Only TEE differs, because its card keeps expansion and dialog state. Adding a detector meant copying that plumbing and editing `DetectorFeatures`, two places in `AppReadyShell` and the application build file.

## Decision

1. **`:core:detector` is the headless detector contract.** It is an Android library without Compose that defines:
   - `Detector<R, M>`: an `id`, `createScanner(context)`, `loadingReport()`, `describe(report)` returning the card model `M`, and `export(model)` returning the `DetectorReport`;
   - `DetectorScanner<R>`, the one port that every data repository implements;
   - `run(context)`, which scans once and returns a `DetectorResult` (id, status, export).
2. **Card models state their headline.** Every card model implements `DetectorHeadline` from `:core:report`: title, status, verdict, summary and an optional finding detail. Its status is the domain verdict, because every mapper sets it from the report's `toDetectorStatus()`. The headless result and the dashboard therefore cannot disagree.
3. **Each detector gains a `detector` layer.** `feature/<name>/detector` holds one object, `<Name>Detector`, which binds the data scanner, the domain loading report and the presentation mapping and export. It is the detector's public face and the only thing the SDK and the detector's UI use. It may depend on the unit's `domain`, `data` and `presentation` layers. Its `ui` layer may depend on it but never on `data`.
4. **The UI contract lives in `:core:ui`.** `DetectorFeature`, `DetectorSession` and the device profile contract move there. `CardDetectorFeature(detector) { model -> Card(model) }` turns any detector into a dashboard session with the scan lifecycle of [ADR 0003](./0003-scan-lifecycle-ownership.md). A detector whose card holds its own state, such as TEE, implements `DetectorFeature` itself on top of its `Detector`.
5. **`:sdk:runtime` is the headless composition root.**
   - `DetectorCatalog` lists every detector in scan-start order. This order is bootloader and TEE first, then the rest by name, as the application has always started them.
   - `DuckDetector` runs detectors without UI.
   - It builds the native libraries and owns the process-level hooks: the app zygote preload, launch evidence capture and the mount-view sampler.
   - It is not a UI module. The boundary policy rejects Compose in it and in anything it depends on.
6. **`:sdk:aar` is the distributable.** It applies AGP's Fused Library plugin to `:sdk:runtime` and every project module that `:sdk:runtime` depends on, directly or transitively, so one AAR carries classes, resources, manifests and native libraries. External libraries stay dependencies in its POM.
7. **`:app` is the UI composition root.** It depends on `:sdk:runtime` and the UI modules. `DetectorFeatures` maps each `DetectorCatalog` entry to that detector's UI feature by id, so both roots start detectors in the same order.
8. **Registering a detector is two lines, and both are checked:** one in `DetectorCatalog` and one in `DetectorFeatures`. Settings, the boundary policy and the build files of both composition roots are derived from the directory layout. A checker fails when a detector module is missing from either catalog, or when a file outside `feature/<name>/` names that detector outside the reviewed allowlist.

## Consequences

- One build produces `:sdk:aar` (a UI-free AAR) and `:app` (the UI APK), and both run the same detector objects.
- A new detector writes its report, verdict, scanner, card model, export and card. The scan lifecycle, session, summary and headless result come from the contracts.
- Scans start in the same order as before. The device profile session now starts after the detectors instead of fifth. It reads only static `Build` fields and the display service, and no detector reads its output.
- Some evidence depends on host integration and reports an explicit unavailable state without it: the app zygote preload, the transparent `NativeActivity` launch, the throne-hunt MIME group anchor and the mount-view sampler. The SDK guide lists each one.
- The Fused Library plugin is incubating. If it regresses, the modules can still be published separately, because `:sdk:runtime` is an ordinary library.
