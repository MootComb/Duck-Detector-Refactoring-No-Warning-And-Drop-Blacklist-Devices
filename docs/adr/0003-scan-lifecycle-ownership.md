# ADR 0003: Serialize detector scans and own dashboard scan progress explicitly

- Status: Accepted
- Date: 2026-09-25

## Context

Every detector view model started a new coroutine for each scan request and neither waited for nor cancelled the previous one. Two rescans could therefore run concurrently, and whichever finished last published its result, even when it had started first. The TEE detector had three entry points that could overlap in this way: the initial scan, a rescan and the revocation-list toggle. Probes touch shared process state: Keystore aliases, bound isolated services and timing measurements. Concurrent scans of one detector can therefore corrupt each other's evidence, not only their display order.

Dashboard progress and scan timing were reconstructed in composition from separate models. Composition restarts on every configuration change, so a scan that had long finished could report a near-zero duration after a rotation.

## Decision

1. `ScanSessionRunner` in `:core:scan` owns the scans of one detector. Each request gets a monotonically increasing `ScanSessionId` and publishes its starting state before it first suspends. It then waits on a mutex for the previous scan, is skipped if a newer request arrived meanwhile, and publishes its result only if it is still the newest request. A scan that has started runs to completion so that probes can clean up shared state. Cancelling the owner's scope still ends everything.
2. Every detector view model routes its scan requests through its own runner, so ownership stays inside the feature and no detector waits on another.
3. `ScanCoordinator` in `:core:scan` observes the `DetectorSummary` flows of all detectors and owns dashboard-wide `ScanState`: ready count, loading state and a `ScanTimeline`. A session starts when coordination starts or when a detector returns to loading after the previous session finished. It finishes the first time every detector is ready. Timing is read through the `ScanClock` port, so the coordinator never touches platform clocks.
4. `DetectorScanViewModel` in `:app` hosts the coordinator with a `SystemClock`-backed clock. Timing therefore survives configuration changes for as long as the detector view models do.
5. Tests in `:core:scan` cover publication order, synchronous visibility of the starting state, suppression of superseded results, skipped queued requests, admission release after failure, cancellation, and session identity. They also cover the timeline rules for completion, restarts and durations.

## Consequences

- An older scan can never overwrite the result of a newer one, and scans of one detector never overlap. This is an intended behavior change: a single scan publishes exactly what it published before, but concurrent requests are now ordered.
- A rescan requested while a scan is running is served after that scan finishes, instead of racing it.
- The dashboard, overview and notifications render one `ScanState`, rather than each deriving progress on its own.
- Detectors still collect their own platform evidence. A shared per-scan snapshot is a separate decision ([follow-ups](../architecture/follow-ups.md)).
