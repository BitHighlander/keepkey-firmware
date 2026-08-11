# RC28 handoff — open findings, owners, and order

Base: `develop` / RC27 `6ae3b964`. Written 2026-08-11 after three audit rounds.

**RC28 is not merge-ready.** Two of the four PRs still carry release-blocking
findings, and #369 is an architectural draft, not a decided design.

| PR | Head | State |
|---|---|---|
| #366 RNG seed-time gate | `2f7f71e6` | RCT boundary fixed; **scope finding open (High)** |
| #367 HASHES.txt labels | `5226cf41` | Green, but **does not fix the stale manifest (High)** |
| #368 storage V17 revert | `280f3b6f` | Lockout + CRC fixed, 23/23; **CRC untestable on emulator (Med)** |
| #369 clear-sign roadmap | `97617a1a` | **8 architectural blockers open** |

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

## 2. Open — release blocking

### 2.1 High — #366 does not establish wallet-wide RNG health

The gate sits only in the generate-mnemonic path. Recovery/import, `LoadDevice`,
PIN and wipe-code changes, upgrades and storage init all create or rewrap
storage encryption keys without passing it.

The narrow fix is sound; the *claim* is not. RC28 must not assert wallet-wide
RNG assurance.

**Design direction (do not scatter call-site checks):** maintain centralised
checked-RNG state and make every security-key draw consume it. One place that
knows the source passed, one place that fails closed, and every consumer routed
through it.

### 2.2 High — #367 leaves the published manifest stale and mislabeled

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

### 2.3 Medium — #368's CRC correction cannot be proven by the test suite

Hardware `calc_crc32(data, word_len)` feeds `word_len` **32-bit words** to the
STM32 peripheral; the emulator implementation loops `word_len` **bytes**
(`lib/board/keepkey_board.c:133-153`). For the new 643-word buffer the emulator
covers 643 bytes, not 2572. The production fix is sound by inspection, but the
suite cannot demonstrate byte 2568 is covered.

**Fix:** correct the emulator to consume words, add a hardware-compatible golden
vector, and add a corruption test targeting byte 2568 specifically.

**Also:** make `flash_temp` explicitly `uint32_t`-aligned. The size assertion
does not guarantee alignment before the cast to `uint32_t *`.

### 2.4 CI

- **#366 / #368 red.** #366's constant-fold is fixed here; re-check.
- **Formatting.** `scripts/format-source-files.sh` under clang-format 22.1.1
  rewrites 40+ untouched files including vendored `pb_*.c`. The local version
  disagrees with CI's — **pin the version before anyone runs it repo-wide**, or
  the formatting job becomes unfixable locally.

### 2.5 Release note, mandatory

**Installing RC28 on a device that ran RC27 wipes it.** RC27 wrote storage V19;
RC28 does not recognise it. That is the anti-rollback policy working as
designed, not a regression. Testers need their recovery phrase first.

### 2.6 Commit the reboot regression

The audit's end-to-end regression — create/reset, set PIN, serialize V17,
reload as after reboot, unlock, compare recovered key — **passed and should be
committed upstream.** The existing 23 storage tests never cross the
serialize/reboot boundary, which is exactly where the lockout lived.

---

## 3. Open — #369 architectural blockers

None are ROM questions. **"Only ROM remains open" is false** and should be
struck from the roadmap.

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

## 4. Suggested order

1. **#368** — emulator CRC + alignment + commit the reboot regression. Closest
   to mergeable; it is the rc28 gate.
2. **#367** — rename/sign/hash ordering and per-artifact instructions. Directly
   protects the hash Vault pins, and explains a defect already found in the field.
3. **#366** — centralised checked-RNG state. Do not ship wallet-wide claims until
   this lands.
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
  a populated checkout and delete the stray `.git` file it brings.
