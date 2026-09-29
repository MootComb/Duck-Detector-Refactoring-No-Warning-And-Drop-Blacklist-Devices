# Bootloader evidence record

Status: reviewed

The Bootloader detector asks whether the bootloader is locked and verified boot is intact, correlating hardware-attested state with the runtime's own properties. Attested state is the stronger evidence; properties can be spoofed.

## Signals

### Attested boot state

- Observable signal: RootOfTrust deviceLocked, verifiedBootState, verifiedBootKey and verifiedBootHash from a fresh attestation.
- Producing subsystem: the bootloader, which passes these values to KeyMint, and KeyMint's attestation.
- Mechanism: KeyMint signs the boot state it received from the bootloader into the attestation extension.
- References: hardware/interfaces security/keymint/aidl KeyCreationResult.aidl (RootOfTrust schema); capability/attestation/EVIDENCE.md.
- Applicability: devices with hardware-backed attestation; AOSP allows Verified with deviceLocked=false on approved test devices.
- Visibility limits: the attestation reaches this app through keystore2 and can be substituted by an interception module.
- Result states: locked and verified, unlocked, self-signed, unverified, failed, unavailable.
- Interpretation: an attested unlock or failed state is danger; a spoofable property alone is weaker.

### Boot consistency

- Observable signal: whether the attested verifiedBootHash matches ro.boot.vbmeta.digest, and whether the hash or key is all zeros.
- Producing subsystem: AVB in the bootloader, which computes the vbmeta digest, and init, which exposes it.
- Mechanism: on a genuine device both views carry the same vbmeta digest.
- References: hardware/interfaces KeyCreationResult.aidl (verifiedBootHash is a SHA-256 digest of the verified images); system/core init/property_service.cpp (androidboot.* to ro.boot.*).
- Applicability: skipped when the attested state is Failed or Unverified, where AOSP does not guarantee the other fields.
- Visibility limits: an empty runtime digest leaves the comparison unperformed.
- Result states: aligned, mismatch, missing, not compared.
- Interpretation: a contradiction between the two views is danger.

### Boot properties and raw boot parameters

- Observable signal: verified boot, lock, AVB and verity properties from several sources, and androidboot.* values in /proc/cmdline and /proc/bootconfig.
- Producing subsystem: init's property service and the bootloader's command line.
- Mechanism: a spoofing module that rewrites properties in one source often misses another.
- References: system/core init/property_service.cpp (ProcessKernelCmdline and ProcessBootconfig); bionic libc/include/sys/system_properties.h; capability/systemproperties/EVIDENCE.md.
- Applicability: /proc/bootconfig exists on Android 12 and later kernels.
- Visibility limits: /proc/cmdline and bootconfig are often unreadable for apps.
- Result states: danger, warning, consistent, unavailable.
- Interpretation: disagreement between sources is itself evidence of rewriting.

### Samsung warranty fuse and Widevine

- Observable signal: ro.boot.warranty_bit and ro.boot.knox.state on Samsung devices, and the Widevine security level and credential through MediaDrm.
- Producing subsystem: Samsung's bootloader, and the Widevine DRM plugin.
- Mechanism: Samsung trips a permanent fuse on unofficial boot images; Widevine L1 is withheld from unlocked devices on many vendors.
- References: Discovery only: the warranty properties and the Widevine behaviour are vendor behaviour, not documented AOSP contracts, and the meaning of the sentinel system ID is unconfirmed. vendor/widevine libwvdrmengine/cdm/core/src/crypto_session.cpp and oemcrypto_adapter_dynamic.cpp at android-9.0.0_r1 show the system ID read from the L1 keybox or OEM certificate, and the CDM falling back to L3 when that credential is invalid.
- Applicability: the warranty properties exist only on Samsung devices; Widevine behaviour varies by vendor.
- Visibility limits: Widevine can be unavailable for reasons unrelated to the bootloader; a wiped or invalid keybox can produce the same credential signs as an unlock.
- Result states: tripped, not tripped, conflict, consistent, unavailable.
- Interpretation: a tripped fuse is danger. A Widevine credential conflict, an L1 claim contradicted by the system ID or the maximum session, is shown as a review item and does not set the verdict on its own; a Java/NDK property mismatch points to an in-process MediaDrm hook and is a warning.
