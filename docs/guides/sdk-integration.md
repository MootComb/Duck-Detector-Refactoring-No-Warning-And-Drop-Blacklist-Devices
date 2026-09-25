# Using the Duck Detector SDK

The SDK is Duck Detector without its UI: every detector, the native libraries and the helper services, in one AAR. The app is built from the same modules, so both run the same probes and produce the same reports.

## Build the AAR

```bash
./gradlew :sdk:aar:publish
```

This publishes `com.eltavine.duckdetector:duckdetector-sdk:0.0.0-SNAPSHOT` to `sdk/aar/build/repository`; pass `-Pduckdetector.sdk.version=<version>` for another version. Assembling the AAR runs `verifySdkAar`, which fails if a headless module is missing from it or a UI library reaches it.

## Requirements

| Requirement | Value |
|---|---|
| `minSdk` | 29 |
| `compileSdk` | 37 or later, the AAR's `minCompileSdk` |
| Kotlin | 2.4 or later. The SDK's Kotlin metadata is 2.4, which the Kotlin bundled with the Android Gradle plugin cannot read, so apply the Kotlin Gradle plugin 2.4 |
| ABIs | `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64` |
| Repositories | The SDK repository, `google()`, `mavenCentral()`, and `https://jitpack.io` for Tencent's `soter-core` |

[`samples/sdk-consumer`](../../samples/sdk-consumer) is a complete application that depends on the published AAR alone, and CI builds it on every pull request.

## Add the dependency

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        maven(url = file("<path to>/sdk/aar/build/repository"))
        google()
        mavenCentral()
        maven(url = "https://jitpack.io")
    }
}

// app/build.gradle.kts
dependencies {
    implementation("com.eltavine.duckdetector:duckdetector-sdk:0.0.0-SNAPSHOT")
}
```

The AAR's manifest brings in the SDK's services, and `soter-core` brings the SOTER keystore permission, library and package query. The SDK itself declares no permissions; see [Permissions](#permissions).

## Scan

```kotlin
val results: List<DetectorResult> = DuckDetector.scan(context)       // every detector, concurrently
DuckDetector.results(context).collect { result -> show(result) }     // each result as it finishes
val su: DetectorResult = SuDetector.run(context)                     // one detector, through its typed object
```

`DuckDetector.detectors` lists every detector in the order `scan` starts them. A `DetectorResult` carries the detector's `id`, its `status` and the structured `report` that the app exports for the same evidence. Each detector moves its own collection off the calling dispatcher.

The contract you compile against is recorded: the public API of `:sdk:runtime`, `:core:detector`, `:core:report` and `:core:evidence` is committed under each module's `api/` directory. CI fails when it changes without the dump being updated, so any change to it is a reviewed diff. Each detector's own typed objects, such as `SuDetector` and its card model, belong to that detector and are not part of this contract.

Results are diagnostic evidence, not a verdict on the device. Read the status as follows:

| `status.severity` | Meaning |
|---|---|
| `DANGER`, `WARNING` | The detector observed evidence; the report says what it saw |
| `ALL_CLEAR` | The probes observed the device and found none of the evidence they look for. This does not prove the device is unmodified |
| `INFO` with `InfoKind.SUPPORT` | A probe was unsupported or unavailable here, so the absence of findings says nothing |
| `INFO` with `InfoKind.ERROR` | The scan failed; the report says why |

## Process hooks

Some evidence can only be captured at points of the process lifecycle that belong to the host. Without these hooks, every detector still runs, and the evidence that needs them is reported as unavailable or failed, never as clean.

### App zygote preload

Name the SDK's preload in the application element, or delegate to it from your own `ZygotePreload`:

```xml
<application android:zygotePreloadName="com.eltavine.duckdetector.sdk.DuckDetectorZygotePreload">
```

It runs each detector's app zygote work, such as Native Root's throne-hunt watch, and then captures the SELinux context validity evidence, before any isolated process forks from the app zygote. Without it, the SELinux and LSPosed carriers report their app zygote evidence as unavailable, and Native Root's throne-hunt carrier reports its collection as failed.

### Throne-hunt anchor

Native Root's throne-hunt stimulus flips a MIME group, and `setMimeGroup` accepts only a group that the calling package declares. Declare it on any activity; the intent filter itself is inert:

```xml
<intent-filter>
    <action android:name="com.eltavine.duckdetector.action.THRONE_HUNT_ANCHOR" />
    <category android:name="android.intent.category.DEFAULT" />
    <data android:mimeGroup="duckdetector-throne-hunt" />
</intent-filter>
```

### Early launch capture

The Mount and Virtualization detectors compare their scan with evidence captured before the first Java activity. The app's launcher is `android.app.NativeActivity` with `android.app.lib_name` set to `duckdetector`. It captures that evidence, then starts `<applicationId>.MainActivity` with the evidence as extras. Call `DuckDetector.captureLaunchEvidence(intent)` from that activity's `onCreate` and `onNewIntent`.

The receiving activity's name is fixed, so reuse this launcher only if your launch activity is `<applicationId>.MainActivity`. Without the launcher, the Mount and Virtualization detectors report the early capture as unavailable.

### Mount-view sampler

The isolated mount-view scanner is ported from PrivIsolated, which creates a WebView before it binds any helper process. The app keeps that order. Before its UI starts, it attaches the invisible view from `DuckDetector.createProcMountSampler(activity)` as a 1x1 child, and destroys it with the activity. Do the same to scan under the same conditions as the app.

## Permissions

The SDK declares no permissions, so the host decides what its process may observe. The app declares these for detection:

| Permission | Used by | Without it |
|---|---|---|
| `QUERY_ALL_PACKAGES` | The package inventory behind Custom ROM, Dangerous Apps, LSPosed, Native Root and Virtualization | Android's package visibility filtering applies, and the inventory records that the permission was not requested |
| `USE_BIOMETRIC`, `USE_FINGERPRINT` | TEE's biometric and SOTER environment checks, which call `BiometricManager.canAuthenticate` | That call requires `USE_BIOMETRIC` |
| `INTERNET`, `ACCESS_NETWORK_STATE` | TEE's online refresh of Google's attestation revocation list | TEE cannot refresh the list online |

The SDK's only visibility declaration is TEE's `<queries>` entry for `com.tencent.soter.soterserver`, which the manifest merger adds to the host. The SOTER environment check needs it to tell a missing service from one that package visibility filtering hides.

The online revocation refresh also needs the user's consent, which the SDK does not ask for. Without it, TEE checks revocation against the bundled snapshot and says so in its report.
