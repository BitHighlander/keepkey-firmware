# RC28 handoff — open findings, owners, and order

Base: `develop` / RC27 `6ae3b964`. Written 2026-08-11 after three audit rounds,
updated the same day after the remediation pass.

| PR | Head | State |
|---|---|---|
| #366 RNG seed-time gate | `e7335677` | RCT boundary fixed; **scope finding addressed** — centralised checked-RNG verdict |
| #367 HASHES.txt labels | `36ae0b56` | Labels + **rename/sign/hash ordering fixed**; manifest generator now runnable by key holders |
| #368 storage V17 revert | `cd984407` | Lockout + CRC fixed; **emulator CRC now matches the peripheral**; reboot regression committed, 24/24 |
| #369 clear-sign roadmap | `abb3b1ed` | 8 blockers **named and ordered**; 4 resolved in text, 3 specified, 1 (custody) is an owner decision |

**RC28 is still not merge-ready**, but for a different reason than before: the
code findings are closed and #369's blockers are now explicit decisions with an
owner and an order rather than an undifferentiated list. Nothing in §3 below can
be closed by an implementer working alone.

## What the remediation pass changed

- **#368** — the emulator's `calc_crc32()` consumed `word_len` BYTES of a
  reflected zlib CRC-32 while hardware feeds `word_len` 32-bit WORDS to the
  STM32 peripheral. It now models CRC-32/MPEG-2 over words, with golden vectors
  independently checkable as the MPEG-2 CRC of each word's big-endian bytes, and
  a test that byte 2568 changes the 643-word CRC but not the 642-word one.
  `flash_temp` is explicitly `_Alignas(uint32_t)`. The audit's reboot regression
  is committed: `Storage.PinUnlocksAfterRebootUnderV17` reports `PIN_WRONG` when
  the hardcoded `PIN_KDF_V19` is put back, and the other 23 tests stay green
  under that same injection — which is the point.
- **#367** — rename now precedes hashing, and generation moved to
  `scripts/release/hash-manifest.sh` so key holders re-run the identical recipe
  over the signed binaries. It reads signed-ness off the artifacts rather than
  being told, so an unsigned manifest says so; `--require-signed` is the
  publish-time gate. It derives the device-image hash from `codelen` instead of
  assuming the file is exactly `256+codelen` bytes, and reports the two
  separately when they differ. Verified end to end on fixtures: the payload hash
  survives signing unchanged, the device-image hash does not.
- **#366** — one latched per-boot verdict plus `random_buffer_checked()`, which
  every key-material draw now goes through: storage key, PIN-KDF salt,
  wipe-code key, U2F key-handle path, `reset_init`'s device entropy, and the
  one-shot OTP randomness block. Each site takes the failure disposition it can
  actually support. Non-key draws (canaries, jitter, U2F channel ids, decoys,
  UUID) and `GetEntropy` are deliberately excluded — gating the audit interface
  would block the measurement that finds a failing source.
- **#369** — §0 lists the eight blockers with severity, resolution location and
  status; §9 keeps only genuine parameters and says they are downstream.

### Known, pre-existing, and NOT caused by this work

**`firmware-unit` cannot complete on a local macOS build.** Six suites hang
indefinitely, each spinning at 100% CPU on a test that drives the shared
`kkconfirm_preload` confirmation driver:

    Authenticator.WipeCancellationFailsClosed
    Ethereum.LiquidityCancellationFailsClosed
    Mayachain.MemoSwapFullFormShowsAffiliate
    Osmosis.MaxSwapAssetsAreRendererPagedCompletely
    Thorchain.MemoSwapFullFormShowsAffiliate
    Confirmation.ExactLengthPagerMeasuresRenderedRows

**Verified at the merge base.** `6ae3b9644` was checked out into the same
worktree, rebuilt, and all six hang identically there — none of this work is
involved. Excluding them, both branches are green and the whole suite takes
about eight seconds:

    firmware-unit  -Authenticator.*:Ethereum.*:Mayachain.*:Osmosis.*:Thorchain.*:Confirmation.*
      #368  327/327      #366  339/339
    board-unit
      #368  7/7 (includes the two new CRC tests)

Two things follow. **If CI for #366/#368 is red on a timeout, look here first**
rather than at the diffs. And *"the storage suite is 23/23"* was always a
filtered result — a full local `firmware-unit` run has never completed on this
platform, so treat any past claim of a clean full run with suspicion. CI builds
inside the emulator Docker image on Linux, which is presumably why #364 merged
green; whether that difference is the display stub, the button simulation or the
UDP transport has not been chased down, and is not this work's to chase.

---

## 1. Fixed this round (verify, do not re-litigate)

- **#368 wallet lockout.** `storage_setPin_impl` hardcoded `PIN_KDF_V19` and set
  `pin_kdf_v2 = true`. It creates the wrap and runs on wallet creation, every
  PIN change, and the V1 upgrade path; under a V17 record the flag cannot
  round-trip, so the next boot derived v15/v16 and every PIN failed. Both the
  derivation and the flag now follow `storage_rewrapPinKdfVersion()`.
- **#368 CRC tail.** `flash_temp[2570]` gave 642 words = 2568 bytes, leaving the
  V17 record's final byte outside the CRC on a path that reaches
  `storage_wipe()`. Now 2572 with static asserts.
- **#366 APT cutoff.** Counter initialised to 1 (NIST's inclusive convention)
  while using the following-matches cutoff: failed at 15 rather than 16, so
  shipped alpha was 3.227e-9, ~3.5x looser than the claimed 2^-30.
- **#366 RCT window reset.** One `started` flag initialised both tests, so a
  five-byte run straddling byte 512 was accepted. RCT and APT now keep
  independent state; two regressions added.
- **#366 compile.** `FailureType_Failure_ProcessError` does not exist.
- **#366 constant fold.** `rng_source_live()` returned bare `true` under
  EMULATOR, making callers' checks always-false branches. Now a real
  draw-twice-and-differ check.

---

## 2. Findings from the audit rounds

Each one is kept with its original text so it is not re-litigated; the
resolution follows it.

### 2.1 CLOSED (was High) — #366 did not establish wallet-wide RNG health

The gate sits only in the generate-mnemonic path. Recovery/import, `LoadDevice`,
PIN and wipe-code changes, upgrades and storage init all create or rewrap
storage encryption keys without passing it.

The narrow fix is sound; the *claim* is not. RC28 must not assert wallet-wide
RNG assurance.

**Design direction (do not scatter call-site checks):** maintain centralised
checked-RNG state and make every security-key draw consume it. One place that
knows the source passed, one place that fails closed, and every consumer routed
through it.

### 2.2 CLOSED (was High) — #367 left the published manifest stale and mislabeled

`release.yml` computes hashes **before** renaming (`:158-199`), then the
checklist (`:317-326`) tells key holders to replace the unsigned binary with the
3-of-5 signed one. Consequences:

- `HASHES.txt` names files that are never published;
- the full-image hash necessarily changes when descriptor signatures are
  inserted, and nothing regenerates it;
- **the published full hash therefore describes the unsigned draft, not the
  binary the device reports** — which is very likely the origin of the wrong
  `32155c11…` v7.14.1 pin found in Vault's table.

Also: the loop applies "compare with `Features.firmware_hash`" and "strip 256
bytes" to **every** `*.bin`, including `bootloader.bin`. Those instructions
describe application firmware only.

**Fix:** rename first, assemble the final signed artifacts, verify the 3-of-5
quorum, then generate both hashes from the final assets, with
artifact-type-specific instructions. #367's labels are correct and can merge;
they simply do not close this.

### 2.3 CLOSED (was Medium) — #368's CRC correction was unprovable by the suite

Hardware `calc_crc32(data, word_len)` feeds `word_len` **32-bit words** to the
STM32 peripheral; the emulator implementation loops `word_len` **bytes**
(`lib/board/keepkey_board.c:133-153`). For the new 643-word buffer the emulator
covers 643 bytes, not 2572. The production fix is sound by inspection, but the
suite cannot demonstrate byte 2568 is covered.

**Fix:** correct the emulator to consume words, add a hardware-compatible golden
vector, and add a corruption test targeting byte 2568 specifically.

**Also:** make `flash_temp` explicitly `uint32_t`-aligned. The size assertion
does not guarantee alignment before the cast to `uint32_t *`.

### 2.4 CI — STILL OPEN

- **#366 / #368 red.** #366's constant-fold is fixed. Before blaming a diff,
  check whether the job timed out in one of the six confirm-driver suites — see
  *Known, pre-existing* above. Those hangs reproduce at `6ae3b9644`, not on
  either branch.
- **Formatting — solved, and the earlier note was half wrong.** CI pins
  **clang-format-20**; the default on PATH here is 22.1.1, which is why
  `scripts/format-source-files.sh` rewrote 40+ untouched files including
  vendored `pb_*.c`. But a matching binary is already installed —
  `/opt/homebrew/opt/llvm@20/bin/clang-format` (20.1.8, brew `llvm@20`) — so the
  job is not unfixable locally, it was being run with the wrong compiler.

  Reproduce CI's check exactly, without touching anything else:

      CF=/opt/homebrew/opt/llvm@20/bin/clang-format
      for f in $(find include/keepkey lib/firmware lib/board lib/transport/src \
                 -name '*.c' -o -name '*.h' | grep -v generated | grep -v '.pb.'); do
        $CF --style=file --dry-run --Werror "$f" >/dev/null 2>&1 || echo "$f"
      done

  Fix a single hunk with `$CF --style=file --lines=A:B -i <file>` rather than
  reformatting whole files. `scripts/format-source-files.sh` still has no pinned
  version — **pin it to 20 before anyone runs it repo-wide.**

  Two violations were found this way and fixed: an 82-column comment in
  `storage.c` (red on #368 since `280f3b6f`, unrelated to the CRC work) and a
  pointer-alignment slip in `u2f.c`.

### 2.5 Release note, mandatory

**Installing RC28 on a device that ran RC27 wipes it.** RC27 wrote storage V19;
RC28 does not recognise it. That is the anti-rollback policy working as
designed, not a regression. Testers need their recovery phrase first.

### 2.6 CLOSED — the reboot regression is committed

The audit's end-to-end regression — create/reset, set PIN, serialize V17,
reload as after reboot, unlock, compare recovered key — passed and was never
committed. The existing 23 storage tests never cross the serialize/reboot
boundary, which is exactly where the lockout lived.

Now `Storage.PinUnlocksAfterRebootUnderV17`, extended to decrypt the secret
section as well as unwrap the key, and verified against a reintroduction of the
hardcoded `PIN_KDF_V19`: it reports `PIN_WRONG`, and the other 23 stay green
under the same injection.

---

## 3. Open — #369 architectural blockers

None are ROM questions. **"Only ROM remains open" is false**, and the roadmap
now says so in its own §0 rather than leaving it to this handoff.

Status after the remediation pass — the findings below are unchanged, and are
kept in full because they are what has to be answered:

| # | Where it stands |
|---|---|
| 1, 6, 8 | **Resolved in the roadmap text.** Opaque cross-variant preservation; proof constraints read only from the verified certificate, with rate-limited advances; one canonical certificate layout, and the Phase 1/Phase 2 "anchor" contradiction resolved by naming a schema root and a delegation root as separate keys. |
| 2, 3, 7 | **Shape specified, decisions named.** The substrate's four parameters (rollback tolerance, checkpoint granularity, wear budget, power-loss state machine) still need an owner; so does the key/quorum inventory, and the choice between authenticated storage and a session-scoped policy. |
| 4 | **Three options written down**, one of which is to state the recovery-only interruption state honestly. Needs a decision, not more analysis. |
| 5 | **Owner decision. Unchanged.** Phase 2 is now explicitly gated on it, because pinning a root in shipped firmware is irreversible. |

| # | Sev | Finding |
|---|---|---|
| 1 | High | Bitcoin-only says freshness may be "absent or inert". It must preserve the authenticated full-firmware freshness field **opaquely** — unable to advance or lower it — or full → btc-only → full resurrects expired delegates. Alternatively full firmware refuses clear-signing when the preserved state is missing, but the transition rule must be explicit. The doc's "shared substrate" and "absent or inert" statements contradict each other. |
| 2 | High | The four-field `SecurityRatchets` facility does not exist. The anti-rollback RFC defines a single 256-step OTP firmware floor. Authenticated flash prevents forgery, not restoration of an authenticated *old* snapshot; a unary OTP counter has 256 lifetime advances and cannot track header heights; committing on every `Finish` still wears flash, and a hostile host can replay ever-longer honest chains to force one advance per proof. Likely shape: OTP-backed coarse generation/checkpoint plus an authenticated journal, with explicit rollback tolerance, checkpoint granularity, wear budget and power-loss state machine. |
| 3 | High | "ROOT SIGNATURE" is an authority class, not a key. Name which root per ratchet. Separation must be cryptographic — distinct keys/quorums, domain-tagged signed transcripts, network/model/variant/format/purpose binding, and negative tests for cross-protocol replay and type confusion. The clear-sign root must never gain authority over firmware or storage epochs. |
| 4 | High | The anti-rollback RFC requires verifying the candidate before erase and old-or-new bootability after power loss. The bootloader erases sectors 7-11 before upload (`usb_flash.c:425-493`) with a single application slot. Needs staging/dual-slot, a signed-digest preflight with streamed verification, or a rewritten invariant that admits recovery-only interruption states. |
| 5 | High | Single-root custody. One dice-generated KeepKey root means one compromise yields globally warning-free false interpretations until firmware replacement. Needs N-of-M across independent devices/locations, plus rotation, backup, disaster recovery and overlapping-anchor transition. |
| 6 | High | `BitcoinFreshnessBegin` lists host-supplied anchor and thresholds. All proof constraints must come from an already-verified certificate; the host may only reference the certificate and stream headers. Also rate-limit persistent advances or require a meaningful checkpoint delta before committing. |
| 7 | High | Blind-sign policy is security-critical persistent state with no specified integrity protection. In unauthenticated public storage a physical attacker enables the downgrade policy directly. Specify authenticated storage or a session-scoped physical-confirmation model, plus behaviour after reset, variant change and corrupted policy. |
| 8 | Med | Certificate schemas conflict across the document: `btc_anchor_*`/`expiry_*` vs `bitcoin_not_before/not_after` vs `epoch` vs `epoch_min/epoch_max`. The acceptance rule checks an epoch "within" a range never defined. Phase 1 ships a built-in anchor while Phase 2 pins it. Needs one canonical signed byte layout, and either consolidated phases or separate schema-root vs production-delegation-root definitions. |

Plus the previously flagged, still-undecided: blind-sign policy stickiness.

---

## 4. Order — what is left

1. ~~**#368** — emulator CRC + alignment + commit the reboot regression.~~ Done.
2. ~~**#367** — rename/sign/hash ordering and per-artifact instructions.~~ Done.
   One thing to carry forward: the checklist now tells key holders to run
   `hash-manifest.sh --require-signed` over the signed binaries. **The first
   real release is the test of that instruction**, and if it is skipped the
   published manifest is wrong again in exactly the old way.
3. ~~**#366** — centralised checked-RNG state.~~ Done. The wallet-wide claim is
   now supportable for key material; it is still **not** an unpredictability
   claim (see the scope note at the top of `lib/rand/rng_health.c`), and the
   release notes must not upgrade it into one.
4. **#369** — decide blockers 1-8 before any implementation. Suggested order:
   substrate (2) → authority model (3) → updater invariant (4) → certificate
   transcript (8) → cross-variant preservation (1) → proof-session inputs (6) →
   policy integrity (7) → custody (5). ROM measurement comes **after**, because
   every one of these changes what gets measured.

---

## 5. Build recipe (took three rounds to find; do not rediscover)

```
PATH=/tmp/kkshim:/tmp/nanopb-gen:$PATH        # `python` shim + "rU"-patched nanopb copy
cmake -B build -S . -DKK_EMULATOR=ON -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
      -DCMAKE_C_FLAGS=-DPB_NO_PACKED_STRUCTS=1 \
      -DCMAKE_CXX_FLAGS=-DPB_NO_PACKED_STRUCTS=1
cmake --build build --target firmware-unit -j8
./build/bin/firmware-unit --gtest_filter='Storage.*'
```

- nanopb 0.3.9.4's generator uses `open(..., "rU")`, removed in Python 3.11 —
  patch a **copy**, not the user's install.
- `protoc-gen-nanopb` needs `python` on PATH, not `python3`.
- Without `PB_NO_PACKED_STRUCTS=1` macOS ARM64 fails to link on unaligned nanopb
  field atoms.
- `deps/sca-hardening/SecAESSTM32` may not populate in a worktree; copy it from
  a populated checkout and delete the stray `.git` file it brings. Same for
  `deps/qrenc/QR-Code-generator`, without which cmake fails at configure time.
- **Do not run `git submodule update --init --recursive deps/crypto/trezor-
  firmware`** to get it. That pulls micropython, tinyusb and friends and takes
  longer than the rest of the build put together. Init the four direct
  submodules non-recursively, then `--recursive` only `deps/qrenc`.
- Run the suite as
  `--gtest_filter='-Authenticator.*:Ethereum.*:Mayachain.*:Osmosis.*:Thorchain.*:Confirmation.*'`
  or it will hang — see *Known, pre-existing* above. Filtered, it takes eight
  seconds; unfiltered it never finishes.
