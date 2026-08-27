# Passkeys in firmware 7.16

Firmware 7.16 adds a USB CTAP2 authenticator alongside the existing U2F
implementation. The legacy `U2FHID_MSG` path remains enabled, so credentials
registered by existing U2F users continue to work.

## Implemented profile

- CTAPHID framing for `CBOR`, `CANCEL`, and `KEEPALIVE`, with the CBOR
  capability advertised during channel initialization.
- CTAP 2.0 `authenticatorGetInfo`, `authenticatorMakeCredential`,
  `authenticatorGetAssertion`, `authenticatorGetNextAssertion`,
  `authenticatorClientPIN`, and `authenticatorReset`.
- ES256 credentials using the existing P-256 implementation and U2F-derived
  credential-key hierarchy.
- Non-discoverable credentials and up to four discoverable credentials.
- ClientPIN protocol 1, including set/change PIN, retry counters, per-power
  cycle throttling, ECDH key agreement, and PIN-token authorization.
- ClientPIN private keys, PIN salts, PIN tokens, and credential-reset
  generations are drawn through the checked RNG path and fail closed. The
  one-shot ECDH private key is erased on its first attempted use.
- On-device user-presence confirmation for registration, authentication, and
  reset. The transport sends CTAPHID keepalives while the button is pending.
- Packed self-attestation. No device-identifying attestation certificate is
  emitted.

The discoverable-credential records, device-bound salted PIN verifier, and
stateless-credential reset generation live in storage V20's previously
reserved V17 plaintext area. Versions 18 and 19 are permanently burned: alpha
builds wrote incompatible clear-sign-identity and PIN-KDF layouts under those
numbers, so reusing either would misparse devices that ran them. V20 does not
parse or carry forward the retired clear-sign identity block; the destination
sector is erased before the bounded V20 record is written. Passkey state is
covered by the same
wear-leveling, CRC, flash readout protection, wipe, and reset behavior as the
rest of device storage. No credential private key is stored: the 64-byte
credential ID wraps a hardened derivation path and is authenticated against the
relying-party ID hash and the active reset generation. A V1 passkey record
temporarily accepts legacy U2F handles during migration. `authenticatorReset`
rotates the generation, disables that legacy fallback, and therefore
invalidates both resident and non-discoverable/U2F credentials.

Writing V20 is a one-way storage migration: firmware that only understands V17
will wipe on downgrade by design. This feature therefore must not ship until
the bootloader security epoch refuses such a downgrade before firmware starts.
`STORAGE_VERSION_LAST_SHIPPED` remains 17 until the signed 7.16 release commit.

## Intentional limits

- USB is the only transport.
- Only ES256 is accepted.
- CTAP 2.1 credential management, enterprise attestation, large blobs,
  `hmac-secret`, and PIN/UV protocol 2 are not advertised.
- The built-in screen/button is user presence, not built-in user verification.
  User verification is supplied through ClientPIN and reflected in the UV bit
  only after a valid PIN-token MAC.
- The FIDO ClientPIN is a separate security-key PIN entered by the platform;
  it is not the wallet-unlock PIN entered on the KeepKey PIN matrix.
- The AAGUID in this development branch is provisional. Replace it with the
  production AAGUID registered in FIDO Metadata Service before release.

## Release gate

Do not ship solely on the unit and firmware builds. A release candidate must
also pass:

1. Implement and validate a bootloader minimum-security epoch that refuses
   firmware unable to read storage V20; test interrupted bootloader updates and
   signed downgrade refusal on every supported board revision.
2. Exact-candidate V17-to-V20 storage migration, interrupted-write, reset,
   recovery, and signed-downgrade tests on real devices upgraded from 7.15.
3. Registration and authentication on current Chrome, Edge, Firefox, Safari,
   Windows Hello, macOS, Linux/libfido2, Android, and iOS where USB security
   keys are supported.
4. Wrong-PIN, power-cycle throttling, cancellation, timeout, exclude-list,
   allow-list, and multiple-account tests.
5. FIDO Alliance CTAP2 conformance testing and an independent review of CBOR,
   ECDH/AES/HMAC handling, storage parsing, and user-presence state transitions.
6. Final flash/RAM/stack measurement with the release compiler and hardware
   soak testing under repeated credential writes.
