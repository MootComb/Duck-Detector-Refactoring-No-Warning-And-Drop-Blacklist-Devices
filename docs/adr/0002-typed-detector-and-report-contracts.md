# ADR 0002: Compose detectors through typed session and report contracts

- Status: Accepted
- Date: 2026-09-25

## Context

The dashboard, the text export and the scan notifications each knew every detector. The dashboard held a view model and card per detector, so adding a detector touched several central files. The export formatter used reflection to read private fields of card models. It relied on an R8 keep rule, and a field rename or minification change would silently drop export content. Card auto-expansion, the result-notice dialog and the scan notification formatter decided what to do by matching titles, so changing a translated title changed behavior. The export banner parsed device identity back out of display text.

These paths make detector semantics depend on presentation details that no compiler checks. AGENTS.md forbids hidden coupling and implicit dependencies of this kind.

## Decision

1. `:core:detector` defines the whole integration surface of a detector. `DetectorFeature` has a `DetectorId` and creates a `DetectorSession`; the session publishes a `StateFlow<DetectorSummary>`, projects its scan as a `DetectorReport`, rescans on request and renders its own card, including any dialogs it owns. `DeviceProfileFeature` does the same for the device specification.
2. `:core:report` defines the typed export model: `DetectorReport` and `DeviceReport`, built from facts, rows and blocks. Each feature's presentation layer projects its own card model into this model. `DashboardReportRenderer` in `:feature:dashboard:presentation` is the only renderer and knows no detector.
3. `DetectorFeatures` in `:app` is the only place that names every detector. Each entry binds a feature to the adapters it scans through, for example `TeeDetectorFeature { context -> TeeRepository(context) }`. The dashboard, export and notification code receive `DetectorSession` lists, `DetectorSummary` values and `ScanState`.
4. Cross-cutting behavior is keyed by types, not by text. The dashboard provides `LocalDetectorIdentity` around each card, and `DetectorAutoExpansionDirective` expands cards by `DetectorId`. The notification formatter branches on the overview's `OverviewVerdict` and `titleDescribesCompletedScan`. The device report carries its identity as typed facts rather than display text.
5. `DashboardExportGoldenTest` renders four seeded scenarios covering every detector's card model and compares them byte for byte with `golden-report.txt`. The golden file was captured from the reflection-based formatter before it was removed, so the typed path is proven to produce identical output.

## Consequences

- Adding a detector means adding its modules and one `DetectorFeatures` entry. No central file changes, and the compiler checks the wiring.
- Export content is part of each feature's typed projection. R8 can no longer break it, and the export keep rule is gone.
- Renaming or translating a title no longer changes expansion, notices or export identity.
- Any change to export output shows up as a golden diff. Regenerating with `DD_UPDATE_GOLDEN=1` is a deliberate, reviewed act.
- `DetectorSession.Card()` is composable, so `:core:detector` is an Android library while the report and scan contracts stay pure JVM ([follow-ups](../architecture/follow-ups.md)).
- Text protocols inside a single feature are out of scope for this decision and are tracked in the follow-ups.
