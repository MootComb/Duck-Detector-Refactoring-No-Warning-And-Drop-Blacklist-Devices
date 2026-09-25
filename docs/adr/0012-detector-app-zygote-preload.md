# ADR 0012: Detectors declare their own app zygote work

- Status: Accepted
- Date: 2026-09-26
- Amends: [ADR 0008](./0008-headless-detectors-and-sdk.md)

## Context

Some evidence can only be captured in the app zygote, before an isolated process forks from it. Native Root installs its throne-hunt watch there, and the SELinux policy capability captures context validity evidence there. `DuckDetectorZygotePreload` in `:sdk:runtime` called Native Root's installer by name. This was the one place where the SDK named a detector outside `DetectorCatalog`, and a second detector with app zygote work would have needed another such call.

## Decision

1. `Detector` gains `appZygotePreload(appInfo)`, whose default does nothing. A detector overrides it for the work it must do in the app zygote.
2. `DuckDetectorZygotePreload` runs every detector's hook in catalog order, in the same position Native Root's call had, just before the SELinux context validity capture. The capture's failure handling and the carriers' ordering are unchanged.
3. Native Root overrides the hook with its throne-hunt watch, and its separate `NativeRootZygotePreload` object is removed.

## Consequences

- A detector that needs app zygote work stays inside its own directory; the SDK names no detector.
- The hook runs without a Context, before any scan, in the app zygote's restricted environment. It must stay small, and a detector whose hook does nothing costs only its object initialisation.
- The public API of `:core:detector` gains the default method, recorded in its API dump.
