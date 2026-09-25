# ADR 0004: Share evidence collection through capabilities and keep interpretation in features

- Status: Accepted
- Date: 2026-09-25

## Context

Several detectors observe the same platform evidence, but each piece of that collection lived inside one feature, and the others reached into it. The virtualization feature owned the helper and isolated process services that mount and native root also used. The TEE feature owned the attestation collector that the bootloader detector needed. The SELinux feature owned the context-validity carrier that LSPosed queried. Package inventory was consumed by five detectors, and the early preload capture by two.

Once features become isolated modules ([ADR 0001](./0001-gradle-module-boundaries.md)), such reach-ins are impossible. They cannot simply be moved to `:core` either, because they contain Android services, JNI and probe code, while AGENTS.md reserves shared infrastructure for abstractions that several features genuinely share. Some collectors also mixed collection with one feature's interpretation, so moving them as they were would have carried a feature's verdicts into shared code.

## Decision

1. Evidence acquisition used by at least two features moves into `:capability:<name>:{domain,data}`. The domain layer holds the evidence types; the data layer holds collectors, native bridges, services and carriers. The capabilities are `attestation`, `earlypreload`, `helperprocess`, `packageinventory`, `selinuxpolicy` and `systemproperties`.
2. A capability collects and never interprets. Each consuming feature derives its own signals and verdicts in its own layers. Where a probe mixed both, it was split first. For example, `DexPathProbe` and `UidIdentityProbe` in the virtualization feature now delegate collection to `DexPathCollector` and `UidIdentityCollector` in `helperprocess` and keep only the signal evaluation.
3. Capabilities depend only on `:core` and on their own layers. They never depend on features or on each other.
4. Packages move with ownership. Classes moved into a capability take the capability's package, so their JNI symbols and manifest component names change with them. The JNI contract check verifies every renamed binding. The merged manifest is compared against a reference that records exactly four renamed components: the two virtualization probe services, the SELinux context-validity carrier service and `AppZygotePreload`.
5. `AppZygotePreload` moves to `:app` as `com.eltavine.duckdetector.AppZygotePreload`. It is a platform entry point that composes the SELinux context-validity preload from `selinuxpolicy` with the native root watch installation, so it belongs to the composition root rather than to either feature.

## Consequences

- A detector cannot reinterpret another detector's verdict, because no verdict is reachable. It can only consume the same evidence.
- A collector exists once, so two features observing the same source use the same implementation and failure states.
- A new capability needs two consumers. A collector used by one feature stays in that feature's data layer.
- Component and JNI names reflect ownership. Class names inside `helperprocess` still carry their historical `Virtualization` prefix until a deliberate rename ([follow-ups](../architecture/follow-ups.md)).
