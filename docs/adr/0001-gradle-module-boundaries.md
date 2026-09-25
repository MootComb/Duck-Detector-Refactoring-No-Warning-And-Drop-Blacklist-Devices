# ADR 0001: Enforce feature isolation with Gradle module boundaries

- Status: Accepted
- Date: 2026-09-25

## Context

Duck Detector was one `:app` module in which detector areas were packages under `features/` and shared infrastructure lived under `core/`. The `data`, `domain`, `presentation` and `ui` boundaries existed only as convention, so any class could import any other class. Detectors reached into each other's internals, central code imported every feature, and Kotlin `internal` protected nothing. Unit tests and lint ran only against `:app`, so there was also no per-area verification.

AGENTS.md requires explicit ownership, low coupling and no cross-feature implementation leakage. Issue #142 asks for these boundaries to be structural rather than conventional, modeled on a ports-and-adapters workspace in which a checked policy states each module's allowed dependencies.

## Decision

The build consists of four module groups with a fixed dependency direction:

```text
:app -> :feature:<unit>:<layer> -> :capability:<unit>:<layer> -> :core:<unit>
```

1. `:core:<unit>` modules hold contracts shared by everything: evidence identifiers, native payload handling, the typed report model, scan lifecycle, the detector contract and shared UI infrastructure.
2. `:capability:<unit>:{domain,data}` modules hold evidence acquisition that several features share ([ADR 0004](./0004-shared-evidence-capabilities.md)).
3. `:feature:<unit>:{domain,data,presentation,ui}` modules hold one detector or supporting feature each. Layers follow fixed templates: `domain` and `presentation` are pure JVM modules; `data` may use `domain`; `presentation` may use `domain`; and `ui` may use both. A feature has only the layers that create a real boundary, so the dashboard and settings have no data or domain layer.
4. Feature units and capability units are isolated groups: no unit may depend on another unit of its own group. Nothing may depend on `:app`, which is the only application module and the composition root.
5. `.github/policies/module-boundaries.json` classifies every module with its kind and its exact list of allowed project dependencies. `DuckDetectorModuleBoundariesPlugin` validates the policy's own consistency and acyclicity, that the build and the policy name the same modules, that each module applies the plugin its kind requires, that every project dependency in every configuration is allowed, and that pure JVM modules pull in no Android artifacts. It runs while each project is configured, so a violation fails every Gradle invocation, including IDE sync, rather than only CI.
6. The validator's unit tests run through `:build-logic:test`. Convention plugins give every module the same Android, Kotlin and test configuration and a `unitTest` lifecycle task. Core and capability modules use Kotlin explicit API mode, because their public surface is a contract.
7. Tests live in the module whose code they test. Tests that deliberately span layers, such as the dashboard export golden test and the SELinux dirty-policy rule test, live in `:app` under `src/test/.../integration/`.

## Consequences

- A new dependency between two features, from a capability to a feature, or from a pure JVM layer to Android fails the build immediately, with a message naming the rule.
- Adding a module requires classifying it in the policy. The policy is the reviewed description of the architecture, not documentation that can drift.
- Kotlin `internal` now means module-internal. Helpers used across modules became explicit public API, which makes the shared surface visible in review.
- Resources are module-scoped under `nonTransitiveRClass`. Strings used by several features moved to `:core:ui`. Lint's translation completeness check lost some context ([follow-ups](../architecture/follow-ups.md)).
- CI runs the tests of every module and `:build-logic:test`. `:app:lintDebug` keeps analysing every module because `:app` enables `checkDependencies`.
- The build has more modules to configure. The configuration cache keeps repeated builds cheap.
