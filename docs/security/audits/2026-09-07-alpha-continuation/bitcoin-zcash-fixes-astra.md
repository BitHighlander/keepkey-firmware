# Bitcoin and Zcash audit fixes

Base SHA at snapshot: ed65a0ce9bbfd06d58a30a834f5245e86310a794, with concurrent authorized changes. Before sources: `/private/tmp/bitcoin-zcash-before/` (original relative paths, 13 files, includes the root's existing complete-Zcash-address wrapper change). No builds, commits, pushes, or crypto-submodule edits performed.

## Verified findings and implementation

### C3-001 — CONFIRMED, plus necessary sequence consistency fix

`signing_init` retains host version/lock_time/expiry. The original final review omitted them. Phase1 inputs retain nSequence; existing BIP143/BIP341 and legacy serialization sign it.

- Mandatory review now shows exact version and lock-time fields. Decred/Overwinter transactions additionally show exact expiry height. Nonzero lock time gets a separate warning distinguishing block height versus Unix time and noting that all-final input sequences disable the lock.
- Every phase1 input shows its exact 1-based input number and unsigned sequence. Non-final values also say that lock/replacement rules may apply. This deliberately avoids silently classifying some sequences as safe/default without showing their signed value, and avoids incorrectly promising network policy across all supported Bitcoin forks.
- Any rejected page aborts and wipes the signing session, before signatures are released.
- Adversarial follow-through found that legacy phase2's internal consistency checksum covered prevout/script type but omitted sequence. Showing only phase1 without addressing that would permit the host to change a reviewed sequence before legacy signing. Both phase1 and phase2 now call one checksum helper that also hashes the exact sequence. This changes ONLY the internal replay-consistency checksum, never any consensus/signature preimage. BIP143/BIP341 already bind phase1 hashSequence to their signatures.

Primary semantics reviewed: https://raw.githubusercontent.com/bitcoin/bips/master/bip-0068.mediawiki (all-final sequence disables nLockTime; relative-lock encoding), https://raw.githubusercontent.com/bitcoin/bips/master/bip-0125.mediawiki (replacement signaling is policy, not a blanket promise of replacement/nonreplacement). No new policy restrictions or consensus serialization introduced.

Tradeoff: exact nSequence disclosure adds a confirmation per input, including default-final sequences. Header review adds a confirmation per transaction, plus expiry and nonzero-lock warnings when applicable. This meets the strict every-signed-field review requirement without additional persistent bookkeeping or misleading default summaries.

### C3-040 — runtime exploit REFUTED, dead optional mode removed

Independent trace agrees the old verify_orchard_digest flag became true unconditionally on every active-session setup and never changed before its consumers. No host-triggerable skip existed. The flag and assignments are nevertheless unused-mode maintenance surface under the authorized dead-code scope: removed them, made action-field requirements and final digest verification unconditional, preserving the digest calculation exactly. Also removed write-only total_amount session storage; the actual summary prompt still uses the local host total as before.

### C3-041 — CONFIRMED contract inconsistency

PCZTAction ignored has_sighash even though transparent input rejects the analogous field. A present action sighash now sends SyntaxError `Host action sighash rejected`, aborts/wipes the signing session, and returns. Presence is rejected even when the byte field is empty; no host digest can silently select old semantics. Device-generated sighash flow remains unchanged.

### C3-042 — no reachable signer exploit; firmware dead APIs removed; crypto patch prepared separately

Whole firmware/include/unit/tool/companion scans confirm no production callers of non-progress key/commitment wrappers, boolean status wrapper, or standalone serialized DiversifyHash helper. Removed those firmware functions/declarations. Tests call the existing live progress variants with null callbacks, compare request_status directly, and use derive_transmission_key's existing gd output for DiversifyHash vectors. No vector coverage dropped.

Crypto dependency is a separate repository at 8a392f70a5d5575ece3dfb35f115d4a4b27f497c. Per root direction, it remains untouched. Full crypto-tree search included ignored/hidden files and fuzz/tests; `/private/tmp/crypto-redpallas-callers.txt` records that the three alternate signing/key-derivation APIs have no dependency-internal callers. Firmware unit tests and the API checker are their only additional local users.

Reviewable, NOT APPLIED patches:

1. `/private/tmp/keepkey-C3-042-crypto.patch` — apply relative to deps/crypto/trezor-firmware. Removes redpallas_sign_digest_for_rk, redpallas_sign_digest, redpallas_derive_rk and their declarations. Keeps the production with_ak signer and all its math unchanged.
2. `/private/tmp/keepkey-C3-042-firmware-companion.patch` — apply relative to the firmware repo after patch1. Ports existing signature/nonce tests to production with_ak, retains independent test-local secret-scalar rk reference, changes the old test that accepted wrong-rk signing into an explicit refusal/no-output assertion, and updates tools/check_pallas_api_boundary.py to forbid the removed APIs globally.

Both patches passed `git apply --check` at the current source state. Their edited proposed source files are in `/private/tmp/redpallas-cleanup-proposed/` for direct review. They were formatted with the firmware repository's clang-format20 configuration. Source-token comparison proves production with_ak, sign_with_rsk, hash_nonce, hash_challenge, derive_rk_from_ak, and verify_digest unchanged by patch1.

Distinction from original finding: redpallas_verify_digest is a legitimate public dependency verification API and meaningful unit-test oracle, so patch1 keeps it. It is not a signing footgun or reachable firmware message surface. `cmake/caches/device.cmake` uses function sections and --gc-sections, so the claim that an unreferenced public API necessarily costs linked ARM ROM is not established merely by its presence in an archive object. Actual linked-symbol proof belongs to root's ARM gate. Removing public dependency APIs is a deliberate compatibility change requiring the separate fork-master/pin integration, not an incidental firmware cleanup.

### C3-043 — runtime leak REFUTED, unnecessary secret retention removed

Independent whole-tree reads confirm ZcashOrchardKeys.sk had no production readers. Removing the member and derivation memcpy saves32 bytes in every retained key structure and prevents keeping the root account spending key throughout a signing session. The local derivation sk remains scrubbed on completion. Tests now compare ask/ak/nk/rivk/dk, preserving deterministic and different-seed/account checks. No derivation arithmetic changed.

## Tests added and validation

Existing files only; no CMake edits:

- `Signing.EveryInputSequenceIsShownExactly`: real framebuffer and consumed-page decisions match independently specified expected strings for final, lock-enabled, replacement-signaling, relative-time, and zero sequences.
- `Signing.NonDefaultHeaderFieldsCannotBypassCancellation`: header, expiry, block-lock and timestamp-lock rejection all refuse approval.
- `Signing.HeaderReviewShowsExactVersionLockAndExpiry`: actual framebuffer verifies full UINT32_MAX version/expiry decimal rendering.
- `Signing.LegacyConsistencyChecksumBindsReviewedSequence`: identical prevout/type with changed sequence produces a different internal commitment.
- `Signing.PhaseOneSequenceRejectionAbortsBeforeProceeding`: drives real signing_init/signing_txack and rejects the new sequence approval, requiring full signing-state cleanup. This catches missing wiring, not only helper behavior.
- `Zcash.LegacyActionSighashAbortsWithExplicitSyntaxFailure`: exercises the real PCZT action handler from an emulator-only minimal active-session fixture, requires the specific legacy-field rejection (not a later missing-action-field failure) and session abort, for present empty and32-byte legacy fields. Fixture/read-only response observers introduce no static storage and are EMULATOR-only.

Passed without builds:

- clang-format20 dry-run/Werror on every touched file.
- git diff --check.
- tools/check_pallas_api_boundary.py against the untouched dependency/current firmware.
- Source-token comparisons against snapshots prove signing_hash_bip341, signing_hash_bip143, signing_hash_zip143, signing_hash_zip243, zcash_compute_shielded_sighash_inner, zcash_compute_transparent_sighash_digest, and zcash_orchard_family_compute_cmx_with_progress unchanged.
- git apply --check for both prepared crypto cleanup patches.

Root must run serialized firmware-unit, board-unit, relevant protocol tests, and ARM resource gates. No test execution/build is claimed here. C3-040/043 hygiene changes rely on preserved existing vectors/control-flow evidence rather than inventing a nonexistent pre-fix host exploit.
