# Attestation capability evidence record

Status: reviewed

The attestation capability collects key attestation evidence for the TEE and Bootloader detectors: a fresh attested key's certificate chain, its parsed attestation extension, its trust root and a boot consistency comparison. It interprets nothing; each consumer decides what the evidence means.

## Signals

### Attestation chain and extension

- Observable signal: the certificate chain of a key generated with an attestation challenge, and the KeyDescription in its leaf.
- Producing subsystem: KeyMint in the TEE or StrongBox, reached through the AndroidKeyStore provider and keystore2.
- Mechanism: KeyMint signs a KeyDescription with the key's authorizations and the RootOfTrust into the leaf certificate's attestation extension.
- References: hardware/interfaces security/keymint/aidl KeyCreationResult.aidl (KeyDescription, AuthorizationList, RootOfTrust); frameworks/base core/java/android/content/pm/PackageManager.java (FEATURE_KEYSTORE_APP_ATTEST_KEY).
- Applicability: devices with a hardware keystore; StrongBox only where advertised.
- Visibility limits: the chain arrives through keystore2, so an interception module can substitute it; consumers must not treat it as self-authenticating.
- Result states: collected with a tier, software only, failed.
- Interpretation: the snapshot records what was returned and how collection ended.

### Trust root

- Observable signal: whether the chain verifies to Google's attestation roots, an AOSP root or a factory root.
- Producing subsystem: the chain's issuer and signatures.
- Mechanism: the analyzer verifies each signature and compares the root with Google's published roots bundled in the app.
- References: Discovery only: Google's attestation root list and revocation feed are Google-published data, bundled or fetched by consent, not an AOSP source.
- Applicability: every attested chain.
- Visibility limits: a revoked or unknown root is only visible if the bundled list is current or the online refresh is allowed.
- Result states: Google, Google RKP, AOSP, factory, unknown.
- Interpretation: consumers weigh the root; the capability only labels it.

### Boot consistency

- Observable signal: whether the attested verifiedBootHash matches ro.boot.vbmeta.digest, and whether the boot hash or key is all zeros.
- Producing subsystem: AVB in the bootloader and init's property import.
- Mechanism: both views carry the vbmeta digest on a genuine device.
- References: hardware/interfaces KeyCreationResult.aidl (verifiedBootHash); system/core init/property_service.cpp (androidboot.* to ro.boot.*).
- Applicability: compared only for Verified and Self-signed states, where AOSP defines the fields.
- Visibility limits: an unreadable digest leaves the comparison unperformed; Verified with deviceLocked=false is allowed on approved test devices and raises nothing.
- Result states: aligned, mismatch, missing, all-zero, not compared.
- Interpretation: hasHardAnomaly marks contradictions; consumers decide severity.
