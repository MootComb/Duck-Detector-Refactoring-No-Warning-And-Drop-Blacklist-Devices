# ADR 0015: The SDK's manifests carry its process hooks

- Status: Accepted
- Date: 2026-09-26
- Amends: [ADR 0004](./0004-shared-evidence-capabilities.md), [ADR 0012](./0012-detector-app-zygote-preload.md)

## Context

Adding the SDK to an application took three manifest steps that named the SDK's internals. The host named `DuckDetectorZygotePreload` in `android:zygotePreloadName`, and the app kept a class of its own only to delegate to it. The host copied the intent filter that declares Native Root's throne-hunt MIME group, which the app kept on `MainActivity`. And the early launch capture started `<applicationId>.MainActivity` by name, so a host whose launch activity had another name could not reuse the launcher. A missed step never failed a build; it only turned evidence into "unavailable".

## Decision

1. `:sdk:runtime`'s manifest names `DuckDetectorZygotePreload` in `android:zygotePreloadName`. The manifest merger takes a library's application attribute when the host declares none and reports a conflict when the host declares another, so a host with its own preload decides explicitly, with `tools:replace` and delegation. The app has no preload class of its own.
2. A module's manifest declares the entries its probes need, on the component that uses them. Native Root declares the throne-hunt MIME group on its carrier service. From Android 11 through main, the package parser collects the MIME groups of every component's intent filters, services included, and `setMimeGroup` accepts any declared group before it schedules the settings write the stimulus relies on. The service is not exported, so the filter stays inert.
3. The launcher starts the activity its own `com.eltavine.duckdetector.launch_activity` meta-data names, read as `NativeActivity` reads `android.app.lib_name`. Without that entry it starts `<applicationId>.MainActivity`, as before.
4. What stays with the host is what a library cannot decide for it: declaring the launcher, calling `captureLaunchEvidence` from the activity it starts, attaching the mount-view sampler, requesting permissions and asking the user for consents.

## Consequences

- A host that only adds the dependency gets the app zygote evidence and the throne hunt. The sample consumer declares the launcher with its own activity, and CI builds it from the published AAR alone.
- The app's merged manifest changed deliberately in two places: `zygotePreloadName` names the SDK's class, and the throne-hunt intent filter moved from `MainActivity` to Native Root's carrier service.
- The moved declarations were checked against AOSP sources and merged manifests, not on a device; the follow-ups list the device checks.
