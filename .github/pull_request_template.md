## Summary

<!-- What changed, and why? Keep this focused on the user-visible or detector-visible outcome. -->

- 
- 

## Sources / Provenance

<!-- See CONTRIBUTING.md: describe research provenance separately from material copied or adapted. A source category alone is not a merge gate. -->

- Knowledge source: <!-- original / public docs (AOSP, ACK, etc.) / black-box observation / reverse engineering / third-party research; multiple categories are fine -->
- Supporting references: <!-- For detector changes, identify the relevant EVIDENCE.md entry and version-specific source or observation where available. -->
- Third-party code, text, or assets reused, and their licence: <!-- identify copied/adapted material and required notices, or "none"; an idea or research reference is not copied material -->
- AI / code-generation tools used: <!-- which tools and for what, or "none"; substantial assistance should use Co-authored-by or Assisted-by in the commit, never Signed-off-by -->

## Change Type

<!-- Check all that apply. -->

- [ ] Feature / new detector capability
- [ ] Bug fix / false positive or false negative reduction
- [ ] Refactor with no intended behavior change
- [ ] UI / copy / localization
- [ ] Build / CI / release / versioning
- [ ] Documentation only

## Affected Areas

<!-- Check all touched risk areas. -->

- [ ] Kotlin data/domain/presentation logic
- [ ] Compose UI
- [ ] Native / JNI / C++
- [ ] SELinux / app_zygote / `/proc` / mount / cgroup behavior
- [ ] AndroidKeyStore / TEE / StrongBox / Binder behavior
- [ ] Zygisk / LSPosed / root-runtime probes
- [ ] Gradle / dependency / versioning / release workflow
- [ ] Notifications / Telegram / QQ / release publishing
- [ ] Strings / i18n / user-facing copy

## Detector Behavior Impact

<!-- Required for detector, reducer, mapper, native, or probe changes. -->

- New signals:
- Changed verdict / severity rules:
- Expected false-positive impact:
- Expected false-negative impact:
- Compatibility notes by Android version / ROM / device class:

## Architecture / Coupling Notes

<!-- Identify the relevant data/domain/presentation/detector/ui layers, shared capabilities, native payload/JNI contracts, and SDK impact. A capability collects evidence; a feature interprets it. Explain any necessary cross-layer change. See docs/architecture/README.md. -->

- 

## Validation

<!-- Paste the exact commands run and their results, including repository guards and any applicable SDK/API checks. Do not claim an unrun test passed; mark N/A and explain why. See CODING_STANDARDS.md §6. -->

- [ ] Compilation passed:
  - Command:
  - Result:
- [ ] Real test completed:
  - What was tested:
  - Result:
- [ ] Unit tests:
  - 
- [ ] `:app:assembleDebug`:
  - 
- [ ] Native build / JNI validation:
  - 
- [ ] Release / workflow validation, if build or CI changed:
  - 
- [ ] Manual app smoke test:
  - 

## Device / Runtime Testing

<!-- Required for TEE, KeyStore, Binder, SELinux, mount, cgroup, Zygisk, LSPosed, native, or root-runtime changes. -->

Tested on:

- Device / ROM / Android version:
- Root / module environment:
- Result:

Not tested on real device because:

- 

Optional comparison testing:

- [ ] Unlocked / rooted / modified device tested:
  - Device / ROM / Android version:
  - Root / module environment:
  - Result:
- [ ] Stock / normal device tested:
  - Device / ROM / Android version:
  - Result:
- [ ] Comparison testing not performed:
  - Reason:

## Documentation And Strings

- [ ] README / docs updated
- [ ] Strings updated where user-facing text changed
- [ ] No documentation or string update needed

Reason:

- 

## Revert / Rollback Plan

<!-- What is the smallest safe rollback if this causes crashes, false positives, broken builds, or release issues? -->

- 
