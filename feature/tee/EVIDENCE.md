# TEE evidence record

Status: reviewed

The TEE detector asks whether this device's hardware-backed keystore behaves like a genuine TEE or StrongBox KeyMint seen through an unmodified keystore2, and whether its attestation chain is consistent with that. It reports evidence; a clean result does not prove the TEE is genuine.

## Signals

### Attestation chain and RootOfTrust

- Observable signal: the attestation certificate chain of a freshly generated key, its trust root, revocation status, and the RootOfTrust fields in the attestation extension.
- Producing subsystem: KeyMint in the TEE or StrongBox, reached through keystore2, which also appends the RKP or factory certificates.
- Mechanism: the attestation extension carries a KeyDescription whose RootOfTrust holds deviceLocked, verifiedBootState and verifiedBootHash; the chain must verify up to a Google or known root and not appear in Google's revocation list.
- References: hardware/interfaces security/keymint/aidl KeyCreationResult.aidl (KeyDescription and RootOfTrust schema); Android key attestation documentation on source.android.com.
- Applicability: KeyMint devices on Android 12 and later, and Keymaster 4 devices behind keystore2's compatibility layer; StrongBox only where advertised.
- Visibility limits: the chain is whatever keystore2 returns to this app, so a process that intercepts keystore2 can substitute it; revocation is checked online only with the user's consent and otherwise against the bundled list.
- Result states: consistent, suspicious, tampered, broken (no hardware-backed trust), inconclusive.
- Interpretation: chain and policy contradictions raise hard or soft policy indicators; a consistent chain is reported as aligned, never as proof that the TEE is genuine.

### Keystore behaviour probes

- Observable signal: key pair consistency, AES-GCM round trip and authorization, key lifecycle, pure certificate entries, update subcomponent, oversized challenges and the dual RSA/EC chains.
- Producing subsystem: the AndroidKeyStore provider in this process, keystore2, and the vendor KeyMint.
- Mechanism: each probe performs a keystore operation whose result a genuine stack fixes, for example a fresh signature that verifies against the leaf certificate.
- References: system/security keystore2/src/operation.rs (operation pruning, BACKEND_BUSY, MAX_RECEIVE_DATA, check_active); hardware/interfaces security/keymint IKeyMintOperation.aidl.
- Applicability: deep checks run only when attestation reports a TEE or StrongBox tier.
- Visibility limits: the probes run in parallel with a probe that fills operation slots, so keystore2 may prune this app's own operations; a probe that throws therefore did not complete rather than failed.
- Result states: passed, failed, did not complete, skipped.
- Interpretation: only an observed contradiction is a failure; exceptions and skipped probes read "Did not complete" or "Skipped" at INFO.

### Operation error path

- Observable signal: the answers to updateAad on a signing operation, update with 0x8001 bytes, and update after abort, through keystore2's private binder.
- Producing subsystem: keystore2 for input length and finalized operations; the vendor KeyMint for updateAad.
- Mechanism: keystore2 rejects more than 0x8000 bytes and answers calls on finalized operations with INVALID_OPERATION_HANDLE itself; updateAad is forwarded to the vendor unchecked.
- References: system/security keystore2/src/operation.rs; hardware/interfaces IKeyMintOperation.aidl ("only applies to AEAD modes", no mandated error); system/keymint ta/src/operation.rs (the reference TA rejects it).
- Applicability: Android 12 and later; the known updateAad vendors are Samsung and Xiaomi on MediaTek.
- Visibility limits: the private binder path needs hidden API access; setup failures leave the probe incomplete.
- Result states: native-style errors, keystore2-enforced divergence, updateAad accepted, partially evaluated, did not complete.
- Interpretation: a keystore2-enforced divergence is a FAIL; updateAad acceptance outside the known vendors is a WARN, because the HAL permits it.

### Native process-side probes

- Observable signal: the binder ioctl in this process (GOT entry, prologue, honeypot timing), a TrickyStore-named mapping, leaf certificate DER fingerprints, tracing and syscall parity.
- Producing subsystem: this app process's libbinder and memory map.
- Mechanism: an interception module that hooks the binder ioctl in the app changes its GOT entry or prologue, or slows keystore-shaped transactions; its library appears in /proc/self/maps.
- References: Discovery only: the GOT, prologue, honeypot and DER signatures follow observed TrickyStore behaviour; TrickyStore's source was not reviewed here. The maps check reads /proc/self/maps as documented in kernel/common Documentation/filesystems/proc.rst.
- Applicability: all ABIs for the maps and DER checks; the prologue decoding is ABI specific.
- Visibility limits: a module that only runs inside keystore2 leaves this process untouched; if libduckdetector does not load, none of these probes run.
- Result states: detected, not detected, native probes did not run.
- Interpretation: the three ioctl observations are one finding and the maps hit another; when the native probes did not run, a consistent verdict reports SUPPORT instead of all-clear.

### Timing side channel and skip signatures

- Observable signal: getKeyEntry timing for attested and non-attested keys through keystore2's private binder, and the exception stacks captured when that measurement cannot start.
- Producing subsystem: keystore2 and any process intercepting its binder calls.
- Mechanism: an interception module that post-processes attested keys adds latency, and some modules answer with characteristic error codes and stacks.
- References: frameworks/base core/java/android/content/pm/PackageManager.java (FEATURE_KEYSTORE_APP_ATTEST_KEY). Discovery only: the TrickyStore and TEE Simulator stack signatures come from collected samples.
- Applicability: needs PURPOSE_ATTEST_KEY; devices that do not advertise app attestation keys are expected to refuse it.
- Visibility limits: timing varies with CPU frequency and load; the proxy numbering in the stack needles depends on this app's own proxy creation.
- Result states: measured, suspicious, skipped with a matched signature, skipped.
- Interpretation: the specific signatures are FAIL worded as matching a known keystore-interception module; the generic binder exception fallback applies only where app attestation keys are advertised.

### SOTER environment

- Observable signal: whether Tencent's SOTER service is reachable and can prepare keys and sessions, and whether its package is visible.
- Producing subsystem: the vendor SOTER Treble service and PackageManager.
- Mechanism: a likely SOTER device with a Simplified Chinese locale, no visible service package and no biometrics is an unusual environment.
- References: Discovery only: the SOTER behaviour follows Tencent's client library; package visibility follows frameworks/base PackageManager.java and the TEE module's own queries declaration.
- Applicability: devices in SoterSupportCatalog.
- Visibility limits: the query is declared in this module's manifest; BiometricManager needs USE_BIOMETRIC from the host.
- Result states: available, damaged, abnormal environment, skipped.
- Interpretation: WARN or FAIL as a supplementary indicator, never a policy verdict.

## Known gaps

- The oversized challenge probe treats any exception as a rejection; distinguishing a length rejection needs the KeyStoreException error code (API 33 and later).
- The update subcomponent probe matches exception message text to recognise key-not-found style failures.
- TeeCardModelMapper chooses the dashboard's top finding by matching report text; see docs/architecture/follow-ups.md.
