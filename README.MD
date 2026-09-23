<p align="center">
  <img src="app/src/main/ic_launcher-playstore.png" alt="DuckDetector logo" width="128">
</p>

<p align="center">
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/stargazers"><img src="https://img.shields.io/github/stars/eltavine/Duck-Detector-Refactoring?style=social" alt="GitHub stars"></a>
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/network/members"><img src="https://img.shields.io/github/forks/eltavine/Duck-Detector-Refactoring?style=social" alt="GitHub forks"></a>
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/releases/tag/nightly"><img src="https://img.shields.io/badge/release-nightly-2F81F7?style=flat-square&logo=github" alt="Nightly release"></a>
  <!-- Replace this placeholder with a dynamic release badge after the first stable release. -->
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/releases"><img src="https://img.shields.io/badge/stable-not%20yet%20released-lightgrey?style=flat-square" alt="Stable release: not yet released"></a>
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/releases"><img src="https://img.shields.io/github/downloads/eltavine/Duck-Detector-Refactoring/total?style=flat-square" alt="Release downloads"></a>
  <a href="https://t.me/duck_detector"><img src="https://img.shields.io/badge/Telegram-Channel-2CA5E0?logo=telegram&logoColor=white&style=flat-square" alt="Telegram channel"></a>
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/blob/main/LICENSE"><img src="https://img.shields.io/github/license/eltavine/Duck-Detector-Refactoring?style=flat-square" alt="License"></a>
</p>

<p align="center">
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/eltavine/Duck-Detector-Refactoring/build.yml?branch=main&amp;style=flat-square&amp;label=build&amp;logo=githubactions&amp;logoColor=white" alt="Main branch build workflow status"></a>
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/actions/workflows/ci.yml?query=event%3Apull_request"><img src="https://img.shields.io/github/actions/workflow/status/eltavine/Duck-Detector-Refactoring/ci.yml?event=pull_request&amp;style=flat-square&amp;label=PR%20checks&amp;logo=githubactions&amp;logoColor=white" alt="Pull request CI: unit tests, lint, and native build"></a>
  <a href="#compatibility"><img src="https://img.shields.io/badge/Android-10%2B-3DDC84?style=flat-square&amp;logo=android&amp;logoColor=white" alt="Android 10 or later"></a>
  <a href="gradle/libs.versions.toml"><img src="https://img.shields.io/badge/Kotlin-7F52FF?style=flat-square&amp;logo=kotlin&amp;logoColor=white" alt="Built with Kotlin"></a>
  <a href="app/build.gradle.kts"><img src="https://img.shields.io/badge/UI-Jetpack%20Compose-4285F4?style=flat-square&amp;logo=jetpackcompose&amp;logoColor=white" alt="Jetpack Compose UI"></a>
  <a href="app/src/main/cpp/CMakeLists.txt"><img src="https://img.shields.io/badge/C%2B%2B-Android%20NDK-00599C?style=flat-square&amp;logo=cplusplus&amp;logoColor=white" alt="C++ / Android NDK native probes"></a>
</p>

<p align="center">
  <a href="#compatibility"><img src="https://img.shields.io/badge/ABI-arm64--v8a%20%7C%20armeabi--v7a%20%7C%20x86%20%7C%20x86__64-555555?style=flat-square" alt="Supported ABIs: arm64-v8a, armeabi-v7a, x86, x86_64; some probes require arm64-v8a"></a>
</p>

<p align="center">
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/issues"><img src="https://img.shields.io/github/issues/eltavine/Duck-Detector-Refactoring?style=flat-square" alt="Open issues"></a>
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/pulls"><img src="https://img.shields.io/github/issues-pr/eltavine/Duck-Detector-Refactoring?style=flat-square" alt="Open pull requests"></a>
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/graphs/contributors"><img src="https://img.shields.io/github/contributors/eltavine/Duck-Detector-Refactoring?style=flat-square" alt="Contributors"></a>
  <a href="https://github.com/eltavine/Duck-Detector-Refactoring/commits/main"><img src="https://img.shields.io/github/last-commit/eltavine/Duck-Detector-Refactoring/main?style=flat-square" alt="Last commit on main"></a>
  <a href="CODING_STANDARDS.md"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen?style=flat-square" alt="Contributions welcome: read the coding standards"></a>
</p>

<p align="center">
  <a href="https://trendshift.io/repositories/44818?utm_source=repository-badge&amp;utm_medium=badge&amp;utm_campaign=badge-repository-44818" target="_blank" rel="noopener noreferrer"><img src="https://trendshift.io/api/badge/repositories/44818" alt="eltavine/Duck-Detector-Refactoring | Trendshift" width="250" height="55"></a>
  <a href="https://trendshift.io/repositories/44818?utm_source=trendshift-badge&amp;utm_medium=badge&amp;utm_campaign=badge-trendshift-44818" target="_blank" rel="noopener noreferrer"><img src="https://trendshift.io/api/badge/trendshift/repositories/44818/daily?language=Kotlin" alt="eltavine/Duck-Detector-Refactoring | Trendshift daily Kotlin ranking" width="250" height="55"></a>
</p>

<p align="center">
  <strong><a href="README.MD">English</a></strong> &nbsp; <strong><a href="README_ZH.MD">简体中文</a></strong>
</p>

<p align="center"><strong>On-device Android environment integrity diagnostics backed by Kotlin and native probes.</strong></p>

# Overview

DuckDetector collects and correlates security-relevant evidence on an Android device. It looks for boot-state changes, root and SU artifacts, runtime injection or hooking, mount namespace anomalies, modified system properties, suspicious applications, KeyStore and attestation inconsistencies, and signs of virtualization.

The app combines a Jetpack Compose interface, feature-oriented Kotlin packages, and a native C++/assembly library. Results are diagnostic signals, not an authoritative statement that a device is secure or compromised.

# Detector coverage

Current feature areas:

`Bootloader` · `Custom ROM` · `Dangerous Apps` · `Kernel Check` · `LSPosed` · `Memory` · `Mount` · `Native Root` · `Play Integrity Fix` · `SELinux` · `SU` · `System Properties` · `TEE` · `Virtualization` · `Zygisk`

`Play Integrity Fix` refers to local indicators associated with integrity-spoofing modifications; DuckDetector does not return an official Google Play Integrity API verdict. The TEE area evaluates Android KeyStore and attestation evidence, including certificate chains, security levels, revocation data, and selected KeyMint, StrongBox, and Soter behavior where supported.

Supporting packages provide the dashboard, device information, settings, update checks, notifications, license information, and common UI infrastructure.

# How it works

- **Feature-oriented structure:** detector areas keep collection, domain models, report mapping, and UI code close to the feature that owns them.
- **Early native capture:** a transparent `NativeActivity` runs before `MainActivity` and records early mount and virtualization evidence.
- **Native probes:** the shared native library performs checks that require direct system calls, `/proc` inspection, timing measurements, linker/runtime visibility, or architecture-specific assembly.
- **Process separation:** selected Zygisk, virtualization, SELinux, and TEE checks run in dedicated or isolated services so evidence can be compared across process boundaries.
- **Evidence correlation:** the dashboard reports individual findings and coverage states instead of treating one heuristic as conclusive.

# Compatibility

| Area | Details |
| :--- | :--- |
| **Android** | Android 10 or later (`minSdk 29`); compiled and targeted against Android API 37. |
| **ABIs** | Native syscall paths are provided for `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64`. Some timing and virtualization trap probes are available only on `arm64-v8a`. |
| **Privileges** | Root access is not required. Android permissions and platform visibility rules still limit what the app can observe. |
| **Device variance** | OEM changes, kernel configuration, Android version, and sandbox policy may cause a probe to be unsupported, unavailable, or lower-confidence. |
| **Network use** | Core device scans run locally. TEE revocation checks always include the bundled snapshot; downloading Google's current revocation feed requires user consent. The app also checks GitHub for Nightly updates after a cold start and when requested from Settings. |

# Architecture

```text
Duck-Detector-Refactoring/
├─ app/
│  ├─ src/main/java/com/eltavine/duckdetector/
│  │  ├─ core/            # Shared platform and UI infrastructure
│  │  ├─ features/        # Detector and supporting feature packages
│  │  └─ ui/              # App shell, navigation, and theme
│  └─ src/main/cpp/       # C++, JNI, and architecture-specific assembly
├─ build-logic/           # Convention plugins and generated-asset tasks
├─ gradle/                # Version catalog and Gradle wrapper files
├─ scripts/               # Repository maintenance scripts
├─ build.gradle.kts
└─ settings.gradle.kts
```

Feature packages generally use these boundaries where they apply:

- `data`: probes, parsers, repositories, JNI bridges, and Android service access
- `domain`: reports, result models, and status definitions
- `presentation`: view models, report-to-UI mapping, and UI state
- `ui`: Compose cards, screens, and feature-specific display models

Native sources are compiled into the `libduckdetector.so` shared library. Kotlin code accesses native results through feature-specific JNI bridges.

# Build

## Requirements

- Android Studio with Android SDK Platform 37 and Build Tools 37.0.0
- JDK 17
- Android NDK 30.0.16138531
- CMake 4.1.2

Dependency and tool versions are defined in [`gradle.properties`](./gradle.properties) and [`gradle/libs.versions.toml`](./gradle/libs.versions.toml).

## Commands

```bash
# macOS / Linux
./gradlew :app:assembleDebug

# Windows
gradlew.bat :app:assembleDebug
```

For the standard local validation path:

```bash
./gradlew :app:compileDebugKotlin :app:testDebugUnitTest :app:assembleDebug
```

Before contributing, read [`CODING_STANDARDS.md`](./CODING_STANDARDS.md).

## Release signing

The build uses the `ciRelease` signing configuration only when all four variables are set:

- `ANDROID_KEYSTORE_PATH`
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`
- `ANDROID_KEY_PASSWORD`

Without the complete set, the local `release` build is signed with the debug key. Do not treat such an artifact as an official release.

# Privacy and limitations

- Detection is performed on the device. The project does not claim that every modified environment can be detected.
- Network-capable features are limited to the consented TEE revocation refresh, GitHub update metadata and changelog checks, and links explicitly opened by the user.
- Results are heuristic and can contain false positives, false negatives, unsupported checks, or incomplete evidence.
- Hardware-backed KeyStore, StrongBox, Binder behavior, `/proc`, SELinux, mount namespaces, and other low-level interfaces vary by device and OS build.

# Project status

<p align="center">
  <a href="https://www.star-history.com/?repos=eltavine%2FDuck-Detector-Refactoring&type=date&legend=top-left">
   <picture>
     <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=eltavine/Duck-Detector-Refactoring&type=date&theme=dark&legend=top-left&sealed_token=z8Kbufd8a78_gJi-_n_U1dbqg3bT3wexECwhrq7Vx1QpfiXBUdPXV5w_rUQSnu86aVeWxIJJENg8tVTng5ul8xki40oK_UhKF3-_gZgvrhWzbtd7OKm9kg" />
     <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=eltavine/Duck-Detector-Refactoring&type=date&legend=top-left&sealed_token=z8Kbufd8a78_gJi-_n_U1dbqg3bT3wexECwhrq7Vx1QpfiXBUdPXV5w_rUQSnu86aVeWxIJJENg8tVTng5ul8xki40oK_UhKF3-_gZgvrhWzbtd7OKm9kg" />
     <img alt="Star history chart" src="https://api.star-history.com/chart?repos=eltavine/Duck-Detector-Refactoring&type=date&legend=top-left&sealed_token=z8Kbufd8a78_gJi-_n_U1dbqg3bT3wexECwhrq7Vx1QpfiXBUdPXV5w_rUQSnu86aVeWxIJJENg8tVTng5ul8xki40oK_UhKF3-_gZgvrhWzbtd7OKm9kg" />
   </picture>
  </a>
</p>

# Disclaimer

This software is provided "as is", without warranty of any kind. It is intended for education, diagnostics, and security research. The developers are not liable for damage, data loss, or system instability resulting from its use. Interpret heuristic findings in the context of the device, OS build, and available probe coverage.

# License

DuckDetector is licensed under the [Apache License 2.0](./LICENSE).
