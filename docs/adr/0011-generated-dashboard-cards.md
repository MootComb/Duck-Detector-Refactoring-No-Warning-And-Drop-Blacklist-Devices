# ADR 0011: The application generates its list of dashboard cards

- Status: Accepted
- Date: 2026-09-26
- Amends: [ADR 0008](./0008-headless-detectors-and-sdk.md), decision 8

## Context

[ADR 0008](./0008-headless-detectors-and-sdk.md) made registering a detector two lines: one in `DetectorCatalog` in the SDK and one in `DetectorFeatures` in the app. The two lines do not carry the same information.

- The catalog line is a decision: its position fixes the order in which scans start, and bootloader and TEE start first.
- The card line only repeated what the directory layout already states: every detector unit has a ui module with exactly one card. `DetectorFeatures` keyed the cards by detector id and ordered them by the catalog, so the order of that list did not matter.

The application already depended on every ui module by discovering them from the directories.

## Decision

1. Every detector's ui layer exports its card as `val detectorFeature: DetectorFeature` in `com.eltavine.duckdetector.features.<name>.ui`.
2. `GenerateDetectorCardsTask` in build-logic writes `detectorCards`, a list of those values for every discovered ui module, into the application's generated sources. It uses plain property references, with no reflection or service loading.
3. `DetectorFeatures` keys `detectorCards` by id and orders the cards by `DetectorCatalog`, as before. It names no detector.
4. The detector touch point policy keeps one registration, `DetectorCatalog`.

## Consequences

- A new detector is its own directory plus its entry in `DetectorCatalog`. The scaffold writes exactly that.
- A ui module that does not export `detectorFeature` fails the application's compilation in the generated file, which names the module's package. `DetectorFeaturesTest` still fails when a catalogued detector has no card, or a card has no catalogued detector.
- The dashboard shows the same cards in the same order.
