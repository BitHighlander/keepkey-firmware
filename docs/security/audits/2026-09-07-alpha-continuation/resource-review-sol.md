# KeepKey second-batch resource and variant-CI review

Date: 2026-09-07 (America/Denver; remote run completed 2026-09-08 UTC)

Scope: read-only review of the exact `ed65a0ce9bbfd06d58a30a834f5245e86310a794` ARM artifacts/logs from GitHub Actions run `34184942840`, followed by source-level review of the uncommitted second-batch delta and the unit-test/CMake/CI variant wiring. I did not edit firmware sources or gates and did not run a build. The dirty source snapshot inspected had 103 tracked files changed (2,576 insertions, 4,370 deletions), plus the already-present untracked build/evidence files.

## Verdict

The two exact ed65 ARM build jobs and both SRAM gates passed. The full image was nevertheless at the boundary: it had only **24 bytes** of static reserve headroom above the required 16 KiB. The dirty second batch is more likely to reduce than increase the static endpoint, principally because it removes the compiled legacy EIP-712/tiny-json implementations and at least 65 bytes of their identified mutable globals. It also removes two of the largest old full-build frames. No reviewed source change plausibly exceeds the existing 7,664-byte largest frame.

That source estimate is not a substitute for the second-batch ARM build. A 24-byte baseline cushion is smaller than normal linker/alignment/compiler variation, so both new full and bitcoin-only ARM SRAM gates remain required before publication.

The new bitcoin-only storage version-ladder test is wired correctly and will compile only in the bitcoin-only firmware-unit image. Consequently, a full native firmware-unit run cannot establish that regression. The current second-batch bitcoin-only unit job is required as evidence.

One concrete compile-definition mismatch remains: `DEBUG_LINK` is an always-defined value macro, but the public storage header uses `#ifdef DEBUG_LINK`. Release translation units therefore see declarations whose implementations are absent. This does not add the debug symbols to the release image without a caller, but it defeats the intended product surface and turns an accidental production call into a link-time failure.

## Exact ed65 CI evidence

Run: `https://github.com/BitHighlander/keepkey-firmware/actions/runs/34184942840`

* Head SHA: `ed65a0ce9bbfd06d58a30a834f5245e86310a794`
* Head branch: `fix/alpha-audit-onepass-20260907`
* Run status/conclusion: completed/failure. The overall run failure does not describe the ARM result; both ARM jobs below concluded success.
* Full ARM job: `build-arm-firmware`, job `101934352842`, success, 2026-09-08 04:09:52Z–04:11:16Z.
* Bitcoin-only ARM job: `build-arm-firmware (bitcoin-only)`, job `101934352660`, success, 2026-09-08 04:09:52Z–04:11:28Z.
* Full artifact: ID `10040534045`, `firmware-v7.16.0-ed65a0c`, 1,529,898-byte archive, GitHub digest `sha256:e646393176cf88606241e8d014ee4bb509e0c2abe2565f9334a256b512be3af0`.
* Bitcoin-only artifact: ID `10040537258`, `firmware-v7.16.0-ed65a0c-bitcoin-only`, 1,211,898-byte archive, GitHub digest `sha256:a49ec114d4558c79f940f6c07cb6cd9c5e3f411f4e9c49f23ce2aa3052d3cc7b`.
* Retrieved full artifact: `/private/tmp/keepkey-arm-ed65-full`.
* Retrieved bitcoin-only artifact: `/private/tmp/keepkey-arm-ed65-btc`.
* Retrieved exact full job log: `/private/tmp/keepkey-ed65-arm-full-logs.zip` (the endpoint returned plain UTF-8 job text despite the suffix).
* Retrieved exact bitcoin-only job log: `/private/tmp/keepkey-ed65-arm-btc-logs.zip` (plain UTF-8 job text).

The SRAM policy is `reserve_min = 16,384` and `frame_margin = 4,096` for both variants in `tools/sram-budgets.json`. The linker independently asserts `_stack - _ebss >= 0x4000` at `tools/firmware/keepkey.ld:75-83`.

### Full ARM image

* `_ebss = 0x2001b7e0`
* `_stack = 0x2001f7f8`
* Static-to-stack reserve: `0x4018 = 16,408 B`
* Reserve headroom: `16,408 - 16,384 = 24 B`
* Largest reported frame: `7,664 B`
* Reserve after largest frame: `16,408 - 7,664 = 8,744 B`
* Headroom above frame-margin rule: `8,744 - 4,096 = 4,648 B`
* Gate result: PASS

Artifact section sizes were `.confidential = 22,392`, `.data = 3,300`, and `.bss = 86,912` bytes.

Largest reported full-build frames:

| Bytes | Function |
|---:|---|
| 7,664 | `u2f.c:207 u2fhid_read_start` |
| 4,224 | `ethereum.c:1402 e712_types_values` |
| 3,760 | `fsm_msg_solana.h:621 fsm_msgSolanaSignTx` |
| 2,624 | `u2f.c:807 u2f_register` |
| 2,400 | `ctap2.c:621 make_credential` |
| 2,160 | `ge25519_double_scalarmult_vartime` |
| 2,016 | `ge25519_scalarmult` |
| 2,016 | `ctap2.c:773 get_assertion` |
| 1,912 | `aes128_cbc_sca_encrypt` |
| 1,912 | `aes128_cbc_sca_decrypt` |
| 1,888 | `eip712.c:653 parseVals` |
| 1,536 | `pallas_hash_to_curve` |
| 1,368 | `ctap2.c:917 client_pin` |
| 1,360 | `ctap2.c:564 get_next_assertion` |
| 1,328 | `solana.c:1379 solana_offchain_message_sign` |

### Bitcoin-only ARM image

* `_ebss = 0x20017be0`
* `_stack = 0x2001f7f8`
* Static-to-stack reserve: `0x7c18 = 31,768 B`
* Reserve headroom: `31,768 - 16,384 = 15,384 B`
* Largest reported frame: `7,664 B`
* Reserve after largest frame: `31,768 - 7,664 = 24,104 B`
* Headroom above frame-margin rule: `24,104 - 4,096 = 20,008 B`
* Gate result: PASS

Artifact section sizes were `.confidential = 20,520`, `.data = 3,292`, and `.bss = 73,432` bytes.

Its largest frame remained `u2fhid_read_start` at 7,664 B. The next four were `u2f_register` 2,624 B, `make_credential` 2,400 B, `ge25519_double_scalarmult_vartime` 2,160 B, and `ge25519_scalarmult`/`get_assertion` 2,016 B each. The full-only Ethereum, Solana, and Pallas frames were absent as expected.

## Dirty second-batch SRAM assessment

This section is an estimate from the source delta, not a replacement measurement.

1. `lib/firmware/CMakeLists.txt:17-27` removes `tiny-json.c` from both products and removes legacy `eip712.c` from the full product. Inspection of the ed65 ELF symbols identified 61 bytes of mutable legacy EIP-712 globals (`confirmProp`, four domain-string pointers, `nameForValue`, `udefList`, and related one-byte state) plus the 4-byte tiny-json `json_errno`. Their removal alone is at least 65 bytes before alignment and exceeds the old full image's 24-byte reserve cushion.

2. `lib/board/messages.c:182-207` changes the already-static 11,264-byte decode buffer from ordinary `.bss` to `.confidential`. The linker places `.confidential`, `.data`, and `.bss` consecutively below `_ebss`; this move changes classification but should not reduce `_ebss` or create reserve. It may change padding/alignment, which is another reason to require the exact link measurement.

3. `lib/firmware/eip712_stream.c:448-480` adds `uint32_t elem_dims[4]` to the array arm of the `Eip712Frame` union. By layout inspection, the other arm still dominates the union: it includes an 80-byte struct name plus a 32-byte hash and state. The extra 16 bytes therefore should not enlarge each frame. The copy in `drive_array_element` is not persistent SRAM.

4. `lib/firmware/eos.c:51` adds `unknown_common_hash[32]` as static state, while `eos_compileActionUnknown` changes the previous function-static 32-byte `hash` to an automatic local. The static endpoint effect should be approximately neutral. New `Hasher hasher_common` and 32-byte digest arrays affect stack only and remain far below the 7,664-byte maximum.

5. `lib/firmware/u2f.c:69` adds one ARM static boolean, `command_in_flight`. The new hook pointer is inside `#ifdef EMULATOR`, so it does not affect ARM. The changed `u2fhid_read_start` logic adds no array or aggregate local and should leave the 7,664-byte maximum stable.

6. The dirty Solana confirmation changes delete several 32- and 45-byte formatting arrays and do not add comparable locals inside `fsm_msgSolanaSignTx`. Its 3,760-byte frame is therefore likely stable or smaller.

7. Removing legacy `eip712.c` removes the old 4,224-byte `e712_types_values` and 1,888-byte `parseVals` frames. Other reviewed changes add only modest local buffers; none plausibly displace the existing 7,664-byte U2F frame.

Expected result: static reserve should improve modestly in the full variant and remain comfortable in bitcoin-only; maximum stack frame should remain at or below 7,664 B. Required evidence: run `tools/check_sram_budget.py` against the newly linked full and bitcoin-only artifacts and retain their `stack-usage.tgz`, maps, and size reports.

## Resource-accounting documentation finding

`lib/firmware/eip712_stream.c:434-441` says that only `.bss` counts against the linker gap and records a measured gap of 17,716 B with 1,332 B headroom. Both statements are unreliable:

* The exact ed65 full artifact measured 16,408 B with only 24 B above the configured reserve floor.
* `.confidential` and `.data` also occupy SRAM below `_ebss`; moving an allocation among those static sections does not recover the gap. This is directly illustrated by the relocated decode buffer.

Smallest remediation after the new ARM build: rewrite the comment to describe all static SRAM through `_ebss` and either cite the newly measured artifact/SHA or omit hard-coded transient numbers. This is a documentation/resource-review finding rather than an observed gate failure.

## Variant test and CI review

The variant wiring is correct for the new storage regression:

* `.github/workflows/ci.yml:386-444` builds both full and bitcoin-only emulator images; bitcoin-only passes `-DKK_BITCOIN_ONLY=ON`.
* `.github/workflows/ci.yml:456-475` builds both ARM products. Full passes `-DKK_CLEARSIGN_ALPHA_ROOT=ON`; bitcoin-only passes `-DKK_BITCOIN_ONLY=ON`.
* `.github/workflows/ci.yml:626-662` runs `make xunit` independently inside both prebuilt emulator images.
* `.github/workflows/ci.yml:672-713` also matrices Python integration across both products and sets both `COINSUPPORT` and `KK_TEST_BUILD_VARIANT`.
* `unittests/firmware/CMakeLists.txt:7-24` keeps common storage, crypto, recovery, CTAP, U2F, signing, and USB tests in both variants. Lines 30-50 append coin-family suites only to full and `bitcoin_only.cpp` only to bitcoin-only. Zcash is further guarded by `KK_ZCASH_PRIVACY` at lines 53-57.
* `unittests/firmware/storage.cpp:837-865` contains the multi-chain refusal test under `#if !BITCOIN_ONLY`.
* `unittests/firmware/storage.cpp:867-905` contains the new bitcoin-only version-ladder regression under `#if BITCOIN_ONLY`. It tests fabricated underlying versions 0 and 10, supported migrations 11, 16, and 17, burned formats 18 and 19, the current version, and a future version.

No second-batch bitcoin-only omission was found in the reviewed test source catalog. The important evidence limitation is temporal: the successful ed65 bitcoin-only jobs predate these dirty tests, and a full-only native run compiles out the bitcoin-only ladder. The second-batch bitcoin-only unit job must compile and pass before the finding is considered regression-covered.

The base CMake definitions for `DEBUG_LINK`, `BITCOIN_ONLY`, and `ZCASH_PRIVACY` are deliberately always present as `0` or `1` (`CMakeLists.txt:167-189`), with source expected to use value guards.

## Concrete compile-definition mismatch

`include/keepkey/firmware/storage.h:222` uses:

```c
#ifdef DEBUG_LINK
```

and declares debug accessors through the matching closing guard. CMake always supplies `-DDEBUG_LINK=0` for release (`CMakeLists.txt:167-170`), so `#ifdef` is true there. The implementations are correctly compiled only under `#if DEBUG_LINK` at `lib/firmware/storage.c:1964` and `lib/firmware/storage.c:2619`.

Concrete trace: release CMake defines `DEBUG_LINK=0` -> a release caller includes `storage.h` -> the debug accessor is declared -> its definition is absent from `storage.c` -> accidental use fails only during linking. There is no current release caller, so the ed65 binary did not gain a callable debug accessor from this mismatch.

Smallest remediation: replace the public header guard with `#if DEBUG_LINK`. Regression strategy: compile a release/preprocessor surface check that asserts the debug declarations are absent at `DEBUG_LINK=0`, or add a simple release-only compile probe after changing the guard. This mismatch predates the dirty batch but remains live in the current tree.

The static-analysis job does not appear to model both product definitions separately; its cppcheck defines do not include the exact `BITCOIN_ONLY`, `ZCASH_PRIVACY`, and `DEBUG_LINK` values. Actual full/bitcoin-only compile jobs do cover syntax and linkage in both products, so this is a static-analysis fidelity limitation rather than evidence of another source regression.

## Required pre-publication evidence

1. New full ARM SRAM gate, map, size report, and stack-usage report. Verify reserve is at least 16,384 B and reserve minus largest frame is at least 4,096 B.
2. New bitcoin-only ARM SRAM gate and the same artifacts.
3. New full firmware-unit pass.
4. New bitcoin-only firmware-unit pass specifically showing `Storage.BitcoinOnlyVersionLadderRejectsBurnedAndFabricatedFormats` ran.
5. Treat the stale EIP-712 SRAM comment and `#ifdef DEBUG_LINK` mismatch as follow-up source findings if they are not corrected in this batch.
