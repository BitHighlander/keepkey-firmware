# SRS — KeepKey Firmware 7.16.0

Software Requirements Specification, IEEE 830 (concise form).

Status: **release-candidate contract**. The implementation is staged after
7.15.0. It is not approved for production until every gate in §4.2 is backed by
evidence from the exact signed candidate.

---

## 1. Purpose and scope

This document is the authoritative contract for the 7.16.0 candidate. The
release is not a single-feature clear-sign change. Relative to the staged 7.15
baseline it contains all of the following:

- KeepKey-root-certified clear-sign delegates and the associated custody
  ceremony;
- the streaming, canonical structured EIP-712 endpoint;
- USB CTAP2/passkeys with ClientPIN and discoverable credentials;
- storage V20, with V18 and V19 permanently burned;
- certified Solana instruction schemas and authenticated address-lookup-table
  account resolution;
- retirement of the legacy Binance signing handlers; and
- the security and correctness remediations already present in the staged
  alpha history, including Orchard/PCZT support.

Open alpha pull requests that are not ancestors of the candidate are not in
scope. A feature is in 7.16 only if it is present in the exact release commit
and named in the final manifest.

### Definitions

- **Root key** — the KeepKey clear-sign key whose public half is compiled into
  firmware. The private half never exists on a device or in CI.
- **Delegate certificate** — a root-signed, scoped and expiring authorization
  for a provider key.
- **Runtime schema** — a user-loaded schema trusted for the current session.
  It remains additive and never inherits certified authority.
- **Certified schema** — a schema whose delegate chain verifies to the compiled
  root and whose scope matches the operation being signed.
- **Suppression** — replacing an opaque/raw review with a complete certified
  structured review.
- **Exact candidate** — the commit and submodule graph from which the signed
  release artifact is reproducibly built.

---

## 2. Release-wide invariants

**R-0.1** 7.16 SHALL be based on the approved 7.15 release commit. The stacked
candidate SHALL reduce to a 7.16-only delta after 7.15 merges.

**R-0.2** All signing paths SHALL fail closed on malformed lengths, impossible
quorums, incomplete certified material, failed cryptographic verification,
failed checked entropy, or user cancellation. No failure may fall through to a
signature.

**R-0.3** The full and Bitcoin-only products SHALL build from the same release
commit. Bitcoin-only isolation tests SHALL remain green.

**R-0.4** Release artifacts SHALL retain signature verification and release
product documentation. The final manifest SHALL record the firmware commit,
every submodule commit, compiler/container identity, artifact hashes, storage
version, and minimum bootloader security epoch.

**R-0.5** `STORAGE_VERSION_LAST_SHIPPED` SHALL remain 17 in every rehearsal and
unsigned candidate. It SHALL change to 20 only in the reviewed signed-release
act, after the storage and downgrade evidence in §4.2 is accepted.

---

## 3. Feature requirements

### 3.1 Certified clear-sign authority

**R-1.1** Firmware SHALL carry only the production KeepKey root public key.
The private key SHALL be generated and held offline under the custody procedure
in `../ClearsignRootCeremony.md`; it SHALL never enter source control, CI, a
developer workstation, or device storage.

**R-1.2** A certified render SHALL require a valid root-signed delegate
certificate, matching purpose/scope, valid time bounds, and a valid provider
signature over the exact schema bytes. Partial, mixed-tier, expired, malformed,
or scope-mismatched material SHALL be rejected.

**R-1.3** Runtime/self-service providers SHALL remain additive. They SHALL show
their runtime identity and SHALL NOT suppress the opaque/raw review. Certified
and runtime tiers SHALL be visibly distinguishable.

**R-1.4** A certified render may replace the opaque review only when every
signed byte and every displayed account/value required by that schema is bound
by native parsing or the verified schema. Otherwise signing SHALL fail closed;
it SHALL NOT silently downgrade from a claimed certified request.

**R-1.5** The release record SHALL state the accepted revocation model and the
blast radius of a compromised delegate. Root provisioning and certificate
issuance require independent human approval.

### 3.2 Structured EIP-712

**R-2.1** The legacy monolithic `Ethereum712TypesValues` endpoint SHALL remain
disabled. 7.16's supported structured path is the streaming
`EthereumSignTypedData` protocol, gated by AdvancedMode until its exact-candidate
hardware evidence is accepted.

**R-2.2** The streaming implementation SHALL request canonical type definitions
and values, reject duplicate/incomplete/non-canonical structures, bind the
displayed domain, primary type, member paths, arrays and primitive values to the
two hashes, and sign exactly
`keccak256(0x19 || 0x01 || domainSeparator || hashStruct(message))`.

**R-2.3** Address, bytes, integer, boolean, fixed-array and struct-array values
SHALL be validated against their declared EIP-712 types. Host cancellation,
unexpected acknowledgements, missing values, or any display/encoding error
SHALL erase the session and produce no signature.

**R-2.4** The EIP-3009/x402 `TransferWithAuthorization` reference vector and
domain-only behavior SHALL match independent host-side hashes and signatures.

### 3.3 CTAP2 and passkeys

**R-3.1** Firmware SHALL implement the CTAP 2.0 USB profile documented in
`../Passkeys.md`, and SHALL advertise only implemented capabilities. CTAP 2.1
credential management, enterprise attestation, large blobs, `hmac-secret`, and
PIN/UV protocol 2 remain unadvertised.

**R-3.2** The production artifact SHALL contain the registered production
AAGUID. The provisional development AAGUID is a release blocker.

**R-3.3** ClientPIN ECDH private keys, PIN salts, PIN tokens, U2F derivation
paths, and authenticator-reset generations SHALL use the checked RNG path and
fail closed. ECDH private keys SHALL be range-checked and erased on first use;
temporary shared secrets and PIN material SHALL be wiped on every exit path.

**R-3.4** `authenticatorReset` SHALL clear the PIN and discoverable records and
rotate a persisted credential generation. It SHALL disable the V1 legacy-handle
fallback so both resident and stateless U2F/CTAP credentials issued before the
reset become invalid.

**R-3.5** User presence, cancellation, keepalive, PIN retry, per-boot throttling,
exclude-list, allow-list, multi-account and GetNextAssertion state SHALL match
the CTAP contract and SHALL not cross transport channels or timeouts.

### 3.4 Storage V20 and downgrade safety

**R-4.1** Storage version 20 SHALL contain the passkey state inside the bounded
V17 reserved area. Versions 18 and 19 SHALL remain enumerated but SHALL never be
reused: incompatible alpha clear-sign and PIN-KDF records exist under those
numbers.

**R-4.2** A V17-to-V20 upgrade SHALL preserve wallet secrets and settings,
initialize passkey metadata safely, and scrub the retired clear-sign identity
block. Interrupted commits SHALL select the newest complete authenticated/CRC
record and never a pending or corrupt record.

**R-4.3** Because older signed firmware intentionally wipes storage it cannot
parse, V20 SHALL NOT ship until the bootloader minimum-security epoch refuses
firmware unable to read V20 before that firmware starts. Signed downgrade,
interrupted bootloader update, recovery, and every supported board revision are
mandatory tests.

**R-4.4** The dormant PIN-KDF V19 rewrap SHALL remain disabled. Storage number
20 does not authorize enabling `STORAGE_PIN_KDF_V19` without its separate
latency, power-loss, downgrade and recovery campaign.

### 3.5 Certified Solana and lookup tables

**R-5.1** Legacy and self-contained v0 Solana messages SHALL be parsed from the
exact signed byte slice. Account counts, instruction counts, indices, compact
integers and trailing bytes SHALL be bounded and canonical.

**R-5.2** A v0 message using address lookup tables SHALL clear-sign only when a
certificate-authorized, transaction-bound LUT proof supplies exactly one
canonical account key for every serialized lookup index. Missing, surplus,
reordered, mixed runtime/certified, or invalidly signed LUT material SHALL fail
closed.

**R-5.3** A reusable instruction schema SHALL match the program, discriminator,
complete instruction-data coverage and every displayed account index. Native
decoders take precedence. Runtime schemas SHALL remain an explicit AdvancedMode
facility and SHALL retain the opaque warning.

**R-5.4** Relay/x402, zero-LUT v0, certified-LUT, malformed proof, program
mismatch, incomplete coverage, and host SDK serialization fixtures SHALL match
firmware parsing byte for byte.

### 3.6 Binance retirement and carried signing safety

**R-6.1** Legacy Binance signing/address handlers SHALL not be reachable from
the firmware dispatch table. Protocol definitions retained for compatibility
SHALL not imply runtime support. The release notes SHALL call out the removal.

**R-6.2** Bitcoin transaction-consistency checks SHALL hash a fixed four-byte
script-type encoding on every ABI. Multisig inputs, outputs and compiler helpers
SHALL reject `m < 1`, `n < 1`, `m > n`, or values above 15 before fee review or
script construction.

**R-6.3** A persistent hardware RNG seed/clock error SHALL latch before the
driver clears hardware evidence. Checked key-material consumers SHALL refuse and
wipe output after a failed verdict.

**R-6.4** Orchard/PCZT signing present in the candidate SHALL retain its
published ZIP-229/244 digest vectors, constant-time Pallas path, progress
contract, T randomness checks, and no-Sapling policy. Release requires
exact-candidate device testing, not emulator vectors alone.

---

## 4. Verification and release gates

### 4.1 Automated candidate gates

The exact commit SHALL pass formatting, static analysis, secret scan, submodule
pin verification, generated-protocol checks, crypto/self-tests, full emulator
build and tests, Bitcoin-only build and tests, Pallas constant-time/boundary
tests, signature-verifier self-test, and reproducible release-product builds.
Warnings or skipped required jobs are failures, not approvals.

### 4.2 External and hardware gates

The release owner SHALL attach evidence for every item below to the final
candidate. These cannot be waived by green unit tests:

1. Production root and delegate custody ceremony, production keys, expiry and
   revocation decision, plus independent human approval.
2. Production AAGUID registration and FIDO Alliance CTAP2 conformance.
3. Passkey registration/authentication on current Chrome, Edge, Firefox,
   Safari, Windows Hello, macOS, Linux/libfido2, Android and iOS wherever USB
   security keys are supported.
4. Device tests for reset invalidation of resident, non-discoverable and legacy
   U2F credentials; PIN set/change/wrong-PIN/blocking; cancellation; timeout;
   exclude/allow lists; multiple accounts; power cycles; and repeated-write
   flash/RAM/stack soak.
5. Exact-candidate V17-to-V20 migration, interrupted writes, wipe/recovery,
   bootloader-update interruption, and signed downgrade refusal on every board
   revision.
6. Streaming EIP-712 screen captures and independent hash/signature comparison
   for canonical positive vectors and malformed/cancelled negative vectors.
7. Certified and runtime clear-sign screen evidence side by side, including
   expired, wrong-scope, tampered and incomplete proofs.
8. Solana legacy, zero-LUT v0, certified-LUT and malformed-proof hardware
   vectors generated by the production host SDK.
9. Exact-candidate Orchard/PCZT hardware signing and signature verification.
10. Final artifact signature verification, hashes, size/stack measurements,
    changelog, recovery warning, support sign-off and named release approval.

---

## 5. Explicit exclusions

- Open alpha changes not present in the candidate ancestry.
- CTAP 2.1 credential management and extensions listed in §3.3.
- Enabling the dormant V19 PIN-KDF rewrap.
- Quorum/multi-root delegation, provider reputation, fiat values, or context
  not cryptographically derivable from the signed bytes.
- Treating emulator, CI, or draft-PR success as a substitute for §4.2.
