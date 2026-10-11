# Dependency update bots

GitHub's native Dependabot checks the Gradle builds (including
`gradle/libs.versions.toml`, plugins and the Gradle wrapper) and the SHA-pinned
GitHub Actions, including the local Android build composite action. The root
Gradle entry discovers the included `build-logic` build; the SDK consumer sample
shares the root catalog and has no independently published dependency to update.
Related Kotlin/AGP changes are grouped together; other library
minor/patch updates and Actions updates are grouped to reduce PR noise.
Major library upgrades remain separate for compatibility review.

Dependabot has no Android SDK package ecosystem. The companion
`dependency-updates.yml` workflow uses `github-actions[bot]` to check NDK, CMake
and Android Build Tools pins in `gradle.properties` against Google's official
SDK repository. It filters out preview revisions, non-stable channels,
obsolete packages and packages without a Linux archive. This matters because
Google's feed can publish NDK previews even on the stable channel.
Package path versions must match the SDK revision metadata, and a complete
archive URL must exist for the 64-bit Linux runner. The updater never downgrades
a pin. Feed/property errors fail the job before PR publication, and stale report
artifacts are removed on subsequent invocations.

Both configurations run at 00:37 UTC (08:37 Asia/Singapore) on calendar days
1, 4, 7, 10, ... of each month. GitHub Dependabot's native cron schedule resets
at month boundaries: this is approximately every three days, **not a strict
rolling 72-hour interval**. GitHub may also delay scheduled jobs. The Android
workflow can additionally be run manually from the default branch.

No PAT, external bot installation or additional secret is required. After this
configuration is merged into the default branch, Dependabot activates and the
scheduled workflow becomes eligible to run. For the Android workflow, enable
**Settings → Actions → General → Workflow permissions → Allow GitHub Actions to
create and approve pull requests** if it is disabled. The workflow does not
approve or merge PRs; this setting is GitHub's permission gate for creating them.

Each complete final Android toolchain pin set gets a deterministic
`bot/android-toolchain-*` branch, even when only some updates remain after a
partial merge. Repeated runs do not duplicate open or closed PRs for that set.
Published branches are never force-pushed. Existing/orphan branches are checked
against their merge base: only the three owned properties may change, without
downgrades, and the complete target set must match the branch name. Unrelated
staged files are rejected before publishing a new branch. New branch content is
also compared against the checked-out base: unrelated properties, comments and
line endings must remain byte-for-byte unchanged, and the report must exactly
describe the staged tool pin changes. The same content validation applies when
reusing an existing branch.

The workflow explicitly dispatches the existing secret-free `ci.yml` on a new
PR branch using `GITHUB_TOKEN`, so a
PAT is not needed to start build verification. Automatic PR-event CI may also
require GitHub's approval; this explicit dispatch is the build verification path.
If publication stops after pushing a branch or creating a PR, the next run
resumes from that state and dispatches CI if no explicit dispatch exists for
the current commit. A failed CI run already exists for that commit and is left
for maintainer review rather than automatically rerun indefinitely.

The bots propose changes for review and do not merge automatically. SDK API
levels (`compileSdk`, `targetSdk`, `minSdk`, minor SDK level and suppression
settings), the Kotlin SDK consumer compatibility baseline, and Git submodules
remain deliberate compatibility decisions; the Android updater edits only
NDK, CMake and Build Tools. The existing toolchain setup reads those same pins,
so CI and local builds stay aligned.

## Local validation

```sh
python3 .github/scripts/test-android-toolchain-updates.py
python3 .github/scripts/test-android-toolchain-publication.py
python3 .github/scripts/update-android-toolchain.py --output-dir /tmp/android-toolchain-update
```

The final command writes available updates to `gradle.properties` and produces
a JSON report and PR body. Use `--properties /tmp/gradle.properties` with a copy
of the file to inspect live updates without changing the checkout, or pass
`--repository-xml <fixture.xml>` for an offline run.

## References and provenance

- [GitHub Dependabot options](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference)
- [Supported ecosystems](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories)
- [Android SDK Manager and channels](https://developer.android.com/tools/sdkmanager)
- [Official SDK repository feed](https://dl.google.com/android/repository/repository2-3.xml)
- [GitHub workflow triggering](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow)

This automation is independently implemented from public official documentation
and the SDK repository format. No third-party implementation was copied.
AI assistance: OpenAI Codex.
