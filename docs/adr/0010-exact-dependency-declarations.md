# ADR 0010: Every module declares exactly the dependencies it uses

- Status: Accepted
- Date: 2026-09-26

## Context

The boundary policy ([ADR 0001](./0001-gradle-module-boundaries.md), [ADR 0007](./0007-derived-module-classification.md)) decides which module may depend on which. It does not decide whether a declared dependency is needed, or whether it is exposed correctly. Several habits had widened the graph:

- UI modules re-exported their presentation modules through `api()`, so every consumer compiled against card models it never used.
- Data modules carried `core-ktx` without using it, which put the `androidx.core` chain into the SDK's POM.
- The app declared three catalog bundles. One of them held `soter-wrapper`, whose classes nothing loads.
- Many modules compiled against types that only a transitive dependency provided, so an unrelated change to a dependency could break their build.

## Decision

1. `./gradlew buildHealth` runs the Dependency Analysis Gradle Plugin on every module. Every kind of advice fails the build: an unused dependency, a used but undeclared one, a wrong configuration, and a compile dependency that is needed only at runtime.
2. A module uses `api` only for types in its public API. Kotlin `internal` declarations, such as the detector cards, are not API.
3. Module structure advice is ignored, because the boundary policy decides whether a module is an Android library. Library families that are versioned and published together are bundles, and a `-ktx` artifact satisfies its base library.
4. The plugin reads erased JVM signatures. Where that misses real API, `DuckDetectorDependencyAnalysisPlugin` records an exception with its reason. There are two: `DetectorId` is a value class that Detector's signatures erase, and `DetectorCatalog.all` exposes `Detector` only as a generic argument.
5. CI runs `buildHealth` in the verify job and uploads its report.

## Consequences

- The app's runtime classpath lost only `soter-wrapper`. The SDK AAR's POM lost `soter-wrapper` and 20 androidx artifacts that no headless module uses. The merged manifest did not change.
- A dependency change shows up as exactly the declaration it needs, and the report names it.
- Declaring a direct dependency on a type that another module also exposes is required, not redundant. The build files state what each module uses.
- The analysis compiles release variants as well, which lengthens the verify job.
