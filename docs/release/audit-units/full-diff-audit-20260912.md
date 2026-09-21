# Full-diff audit of the 7.14.3 candidate

Every changed file of this candidate was reviewed against its base, in
subsystem-sized chunks, by reviewers that had the base version, the current
file and the ability to grep callers. Findings rated P1 or P2 were then
re-checked by three independent reviewers along separate lines of attack --
is the path reachable, does the consequence matter on a shipped release, is it
already covered -- and a finding survived only when at least two of the three
failed to refute it.

Status of each finding below:

- **FIXED** -- corrected on this line, with a test where a seam exists. Where
  a control build was possible, the unfixed code was built and the test
  confirmed to fail against it; where no seam exists, the test or the commit
  message says so rather than implying coverage.
- **refuted on re-check** -- the re-check found the claim does not hold on
  this head. No change made.
- **open** -- real, not addressed in this pass. Each is named so a reader can
  weigh it rather than discover it.
- **triaged by reading** -- P3, read and judged not to warrant a change in a
  release pass. Not individually re-checked by the three-reviewer process.


Counts: 21 fixed, 2 refuted on re-check, 0 open, 23 triaged by reading (46 findings touching this line).


## Fixed

- **F028** (P3, `lib/rand/rng_health.c`) — random_buffer_checked() ignores a hardware seed/clock error latched during the draw itself
- **F029** (P3, `.gitmodules`) — python-keepkey tracking branch does not contain the pinned commit; --remote silently rewinds the pin 5 commits
- **F034** (P3, `lib/firmware/solana.c`) — "Maximum priority fee" can be lower than the fee the runtime actually charges
- **F035** (P3, `lib/firmware/ethereum.c`) — TRANSFER amount screen can show a stale WAN ticker left by an earlier request
- **F059** (P3, `lib/firmware/fsm_msg_ethereum.h`) — process_ethereum_xfer() leaves a derived private key in the shared fsm_derived_node scratch on two error returns (raised on 7.15; this line carried the same code)
- **F062** (P3, `unittests/firmware/rng_health.cpp`) — Boot RNG gate (rng_health_gate / rng_source_live) is never entered by the suite that claims to cover it
- **F066** (P2, `lib/firmware/fsm_msg_ripple.h`) — New RIPPLE_MAX_DROPS bound refuses legitimate XRP payments above 100,000 XRP
- **F069** (P2, `lib/firmware/storage.c`) — storage_commit() silently discards writes on a bitcoin-only-locked device, so ChangePin/ChangeWipeCode/ApplySettings/ApplyPolicies report Success after an on-device approval and persist nothing
- **F070** (P2, `lib/firmware/fsm_msg_common.h`) — btcOnlyLocked guard covers only the two ceremonies; ChangePin/ChangeWipeCode/ApplySettings/ApplyPolicies still report success on a write that never happens
- **F071** (P2, `lib/firmware/fsm.c`) — Transport failure handler now aborts all workflows in production, and BITCOIN_ONLY makes every multi-chain message an "Unknown message" -- a host probe kills an in-flight recovery
- **F096** (P2, `docs/release/7.14.3-COMBINED-CANDIDATE.md`) — Candidate receipt pins a device-protocol commit that cannot build the shipped head, and its acceptance evidence predates the whole dice feature
- **F097** (P3, `docs/security/7.14.3-bitcoin-only-dice-audit-sop.md`) — The dice audit SOP states security invariants the shipped two-mode ceremony deliberately violates
- **F109** (P3, `.github/workflows/release.yml`) — Bitcoin-only release asset ships with a reproduction command that reproduces the other binary
- **F146** (P3, `lib/firmware/tiny-json.c`) — tiny-json `errno` -> `json_errno` rename not propagated to 7.14.3
- **F156** (P2, `lib/firmware/storage.c`) — 7.14.3 commit CRC also excludes the last byte of the V17 record, with no test whatsoever
- **F157** (P3, `tools/firmware/keepkey.ld`) — 7.14.3 is missing the 16 KiB runtime-SRAM link-time ASSERT that 7.14.2 and 7.15 both carry
- **F196** (P3, `lib/firmware/signing.c`) — sig_with_hashtype[73] is one byte too small for the size it is written for, so the OOB write it was added to remove is only prevented by the separate cap (raised on 7.15; this line carried the same code)
- **F219** (P2, `docs/release/7.14.3-COMBINED-CANDIDATE.md`) — Release-candidate receipt (pins, ELF hashes, SRAM reserves, test counts) is 44 commits stale and wrong at head
- **F220** (P3, `docs/security/7.14.3-bitcoin-only-dice-audit-sop.md`) — Dice audit SOP's stated security invariants are contradicted by the shipped dice modes
- **F230** (P3, `include/keepkey/firmware/tiny-json.h`) — 7.14.3 applied half of the tiny-json header fix: extern "C" added, errno rename dropped
- **F239** (P2, `docs/release/7.14.3-COMBINED-CANDIDATE.md`) — Recorded dependency pins predate the release's own dice protocol commits

## Refuted on re-check

- **F107** (P3, `.github/workflows/ci.yml`) — Presign report binds both ARM variants but contains only full-variant test evidence
- **F108** (P2, `scripts/generate-test-report.py`) — Fail-closed required-case set is 7.14.2's; no 7.14.3 control, and `skip` is accepted

## Triaged by reading (P3)

- F026 (`lib/firmware/coins.c`) — New m/86' branch in path_mismatched() is dead: account_prefix() still rejects purpose 86'
- F027 (`lib/firmware/fsm_msg_ripple.h`) — RIPPLE_MAX_DROPS (100,000 XRP) refuses payments the base signed correctly
- F030 (`lib/firmware/solana.c`) — Default CU limit ignores builtin 3,000-CU allocation (SIMD-0170), so 'Maximum priority fee' is overstated ~66x for the most common Solana tx
- F031 (`unittests/board/board.cpp`) — Source-overflow refusal test stays green with the refusal removed (NULL canvas + 99-page cap)
- F036 (`lib/firmware/ethereum.c`) — New Wei fallback refuses native values of 1e27 wei or more on unmapped chains (32-byte buffers)
- F037 (`lib/firmware/app_layout.c`) — Raising 2-line bech32 addresses to y=44 fuses the QR's lit border row onto the first line's glyphs
- F038 (`unittests/firmware/rng_health.cpp`) — TrippingBytesAreWipedNotReturned never reaches the post-draw wipe it is named for
- F039 (`unittests/firmware/rng_health.cpp`) — Hardware fault-latch tests only exercise a seam that already does latch-then-reset
- F040 (`unittests/firmware/test_board.cpp`) — One-bootstrap guard is bypassed by storage_passphrase.cpp's direct timer_init()
- F041 (`unittests/crypto/bip340.cpp`) — ZeroSTakesTheSpecPath passes whether or not the s==0 guard it claims to pin is absent
- F043 (`unittests/firmware/CMakeLists.txt`) — Bitcoin-only firmware-unit silently drops all coin-table/BIP32-path coverage with coins.cpp
- F050 (`lib/firmware/solana.c`) — Explicit SetComputeUnitLimit is not clamped to 1,400,000, so "Maximum priority fee" can overstate the true ceiling by ~3000x
- F051 (`lib/firmware/fsm_msg_solana.h`) — ATA Create never shows the funding account that is debited rent, unlike the analogous System CreateAccount screen
- F052 (`unittests/board/board.cpp`) — Exact-byte page test asserts the tautology the producer already enforces
- F053 (`tools/verify_dice_seed.py`) — Verifier infers the dice ceremony mode from an optional flag and reports a mismatch as device fraud
- F063 (`unittests/firmware/rng_health.cpp`) — PersistentHardwareFaultLatchesBeforeReset is byte-for-byte equivalent to the transient test in the only build it runs in
- F064 (`unittests/firmware/rng_health.cpp`) — IrregularChunkingMatchesOneShot only asserts the failing direction, leaving the fail-closed hazard uncovered
- F098 (`docs/DiceEntropy.md`) — Published MIXED derivation writes the domain tag as a C string literal that parses to different bytes than the firmware uses
- F110 (`.github/workflows/release.yml`) — HASHES.txt asserts a builder image that this workflow never used, from an unchecked duplicate of the digest
- F111 (`.github/workflows/release.yml`) — bootloader.bin and every other non-firmware.keepkey output is silently dropped from the release
- F112 (`.github/workflows/ci.yml`) — Digest-pinning BASE_IMAGE disables the base-image save/load cache on every cache hit
- F113 (`scripts/generate-test-report.py`) — Workflow-metadata binding check compares the SHA against itself when the env var is unset
- F221 (`docs/release/REHEARSAL-SOP.md`) — SOP anchors the foundation's immutable identity to a manifest that does not exist in the tree

## Re-checked at head

- F238 — `layout_debuglink_watermark()` is declared in `layout.h` and defined in
  `layout.c` at this head, so the DEBUG_LINK device image links again. The
  finding was raised against the head that deleted it.
