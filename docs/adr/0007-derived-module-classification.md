# ADR 0007: Derive module inclusion and classification from conventions

- Status: Accepted
- Date: 2026-09-25
- Amends: [ADR 0001](./0001-gradle-module-boundaries.md), point 5

## Context

ADR 0001 made module boundaries structural. Every module was listed twice: once as an `include` in `settings.gradle.kts` and once as a member of `module-boundaries.json`, together with its exact list of allowed project dependencies. That list repeated the module's own `build.gradle.kts`.

A new detector therefore meant eight hand-written entries outside its own directory: four includes and four policy members. None of them carried any rule that the feature layer templates did not already state. The per-module lists also did not make dependencies minimal. They only recorded which edges already existed, so an unused edge stayed allowed for as long as it was listed.

Compose was allowed anywhere. The JVM purity rule kept Android out of `domain` and `presentation`, but nothing stopped a `data` layer or a core contract from pulling in Compose. A UI-free library artifact needs exactly that guarantee.

## Decision

1. `settings.gradle.kts` includes every directory that holds a `build.gradle.kts` at its group's depth: `core/<unit>`, `sdk/<unit>`, `capability/<unit>/<layer>` and `feature/<unit>/<layer>`. The Gradle path mirrors the directory.
2. Policy schema 2 classifies modules of layered groups (`:feature`, `:capability`) by their path. Each layer template states its module kind, whether it is a UI layer, the layers of the same unit it may use (`may_depend_on`), and `*` globs over the modules outside the unit it may use (`may_use`). A new unit needs no policy entry.
3. The composition root and every module of a group without layers (`:core`, and later `:sdk`) stay explicit members, each with its kind, UI flag and allowed dependencies. Allowed dependencies may be `*` globs. Members may not sit inside a layered group, so no feature module can escape its template.
4. Direction, unit isolation, JVM purity and the composition-root rule still apply to every edge that any module declares. Layer templates must be acyclic, and so must the explicit members.
5. UI isolation is a rule. Only UI modules (the `ui` layer, `:core:ui` and the composition root) may apply the Compose compiler or declare an artifact matching `ui_only_dependencies`. No module that is not UI may depend on a module that is.
6. Each module's `build.gradle.kts` is the single declaration of its dependencies. The policy decides whether an edge is architecturally allowed, not whether it is still needed.

## Consequences

- Adding a feature or capability unit touches only its own directory. A misplaced edge still fails configuration, with a message naming the layer rule, for example `'data' layers of :feature may only use [...] outside their unit`.
- The policy file describes the architecture (about 190 lines) instead of enumerating it (about 900 lines).
- A feature layer may now use any capability or core module its template names, so which capability a feature consumes is visible in that feature's build file rather than in the policy. Unit isolation, direction and layer templates are unchanged.
- Whether a declared dependency is actually used is not checked here; minimal dependencies need a separate usage-based check.
