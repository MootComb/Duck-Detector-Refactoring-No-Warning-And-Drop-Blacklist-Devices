# ADR 0013: Detectors declare the consents they need

- Status: Accepted
- Date: 2026-09-26
- Amends: [ADR 0008](./0008-headless-detectors-and-sdk.md), [ADR 0011](./0011-generated-dashboard-cards.md)

## Context

TEE fetches Google's attestation revocation feed only after the user allows it. The application asked for that permission by reaching into TEE's data layer. Its startup policy, app shell and tests read and wrote `TeeNetworkConsentStore` and `TeeNetworkPrefs`. The settings screen had a CRL switch of its own, and the shell looked up the TEE session by `TeeDetector.id` to rescan it. These seven files were the application's only detector touch point exceptions. A second detector needing a user decision would have repeated the same wiring. SDK hosts had no way to find the choice except by reading the guide.

## Decision

1. `:core:detector` defines `DetectorConsent`: a `ConsentId`, a `Flow` of the current `ConsentDecision` (undecided, granted or declined), and `decide(context, granted)`. `Detector.consents` lists a detector's consents and is empty by default. Consent ids are unique across the catalog.
2. The detector owns the decision's storage and reads it during its scans. Declining, or never deciding, only limits what a scan may do; it never stops the scan, so consents do not block the startup gate.
3. `:core:ui` defines `ConsentCard`: the consent plus a `ConsentPrompt` for the startup policy screen and a `ConsentSetting` for settings, each with its own icon and string resources. `DetectorFeature.consentCards` supplies them, so the words live in the detector's ui module.
4. The application collects every feature's consent cards in catalog order. It waits for all decisions to load before it leaves the startup gate. It shows one startup card per consent, between the live update card and the package manager card, and one settings switch per consent. After the user changes a switch, it calls `decide` and rescans the session of the detector that owns the consent. A startup check fails if a feature's consent cards and its detector's consents differ.
5. TEE declares `TeeRevocationNetworkConsent` over its existing store. It maps the preferences in the order `CrlStatusService` reads them, and it moves its thirteen strings, unchanged, into `feature/tee/ui` for all nine locales.

## Consequences

- The application names no detector outside the generated card list, so its seven touch point exceptions are gone.
- A detector that needs a user decision adds it to its detector object and its ui module; nothing central changes.
- SDK hosts find every choice through `DuckDetector.detectors` and record answers through the same contract the application uses.
- The TEE startup card and settings switch look and behave as before. The switch is on only for a granted decision. This matches the old `consentGranted` reading for every state the store can hold, because the store always records that the user was asked together with the answer.
- `:core:detector` exposes kotlinx-coroutines-core, because decisions are a `Flow`.
