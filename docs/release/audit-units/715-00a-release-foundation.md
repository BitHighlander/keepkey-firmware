# 7.15 block 00a — release-foundation receipt

Status: `LOCAL-QUALIFIED` after Copilot review 5285511297 on `506ea3e12`; findings 017–018 pass the final local contract, but the replacement head is not yet hosted-qualified. Prior run 35799306854 passed on `506ea3e12`; final head/tree belong in the PR attachment.

- Adjacent base: `fc1e93746132553ad98ed60f4847c8d770732bf9`.
- Companion: `98c717ff2204124bf67cc78cab8ca1d501fd4e92` (fast-forward canonical `reconcile/upstream-sync` from `c1b136a`); nested device-protocol: `dd9c85dc747cf965fb0e7bf49615dc9e7568ee65`; consumed pins reproduced cleanly.
- Direct device-protocol: `8545cd5b615f5832374afbf06387a3f28869285e`; Trezor crypto: `e8ce42f873dbdae16017122bb4fe8a949f825fc0` ([dependency PR #12](https://github.com/keepkey/trezor-firmware/pull/12)); inactive vendor/test trees excluded.

This foundation carries 7.14.x signing/storage/display/recovery/entropy/authorization hardening and both product build/report/SRAM/artifact gates; later ERC-7730/runtime-provider/chain features are excluded. Signed data is disclosed or refused, aborts clear state, invalid storage cannot partly mutate, and entropy/signature verification fails closed.

## Qualification ledger

| Gate | Historical evidence | Current candidate |
| --- | --- | --- |
| Native Docker | 193 regular / 93 bitcoin firmware, 16 board, 19 crypto pass | Final fix images: 194 regular / 92 bitcoin firmware, 20 board, 19 crypto pass; timer and animation regressions hang before fix and pass after |
| Companion integration | 559 pass/272 skip regular; 334 pass/497 skip bitcoin-only | Exact Docker entrypoints: 559/272 regular and 334/497 bitcoin-only pass/skip, zero failures |
| Strict OLED | 64 pass/23 skip regular; 25 pass/62 skip bitcoin-only | Exact Docker entrypoints: 64/23 regular and 25/62 bitcoin-only pass/skip, zero failures |
| ARM/SRAM | Both pass; 21,312/28,268 B reserves; largest frame 12,416 B | Both pass; same reserves and 12,416 B largest frame |
| Static/provenance | Cppcheck 109 files/0 findings; actionlint, format, secret, clean pin and failure probes pass | Cppcheck 109/0 on prior head and changed `layout.c`/`timer.c`/`libkkemu.c` 0 findings; clang-format, actionlint and diff check pass; clean pin and secret checks to be repeated on final head |
| Hosted | [Old head](https://github.com/BitHighlander/keepkey-firmware/actions/runs/35629160260); [prior PR head](https://github.com/BitHighlander/keepkey-firmware/actions/runs/35782012448) green | [Run 35799306854](https://github.com/BitHighlander/keepkey-firmware/actions/runs/35799306854) passed on `506ea3e12`; new fix head pending |

Reviewed skips use `KK_RELEASE_MISSING_CAPABILITIES` or product/version gates; dylib/registry have separate gates, PIN-timeout/empty burned-version have alternate coverage, and seven Osmosis plus five boot/upgrade tests run in both profiles. Flaky retries do not count.

## Findings and closure evidence

Owner: BitHighlander release; local reviewer: Codex. Findings 001–012 affect `f099dfcd8`, 013–015 affect `8e49807a3`, 016 affects `0ad2cdfb6`, and 017–018 affect `506ea3e12`. Review threads and the gate ledger supply verification.

| ID | Failure and required disposition |
| --- | --- |
| 001 | Restore PR-scoped concurrency; inspect hosted workflow trigger. |
| 002 | Preserve cppcheck diagnostics under `bash -e`; controlled nonzero probe. |
| 003 | Reuse the exact built emulator image in integration; both profiles. |
| 004 | Required ARM failure must propagate; guard only optional outputs. |
| 005 | Remove undeclared `zcash-privacy` product; regular includes Zcash. |
| 006 | Populate alternate nanopb descriptor capacities; shape regression. |
| 007 | Put exact `kkemu` in companion image; boot-version tests execute. |
| 008 | Pin canonical companion; seven Osmosis controls execute. |
| 009 | Restore RNG draw-completion fault wipe/refusal and reset seam. |
| 010 | Report-copy/status failures propagate after xunit; both profiles. |
| 011 | Reject unbounded SRAM records; both ARM gates and crypto PR #12. |
| 012 | Timer test uses shared one-time board fixture; shuffled suite. |
| 013 | 7.14.3 is non-release foundation; final #843 sets 7.15.0; thread resolved. |
| 014 | OTP draw/write/read/lock failures wipe salt and halt before storage; injected failures, both native profiles and both ARM gates pass. |
| 015 | Nano unrenderable amount refuses signing: old code returns signed `true`, fixed code `false` with no signature; isolated/shuffled and regular native pass. |
| 016 | Hosted recovery read stale `Success("Device wiped")` at `RecoveryDevice`. Pre-fix Docker reproduced at cycles 50/190; companion handshake assertions saw premature backup-page reply at cycle 45. Root: `confirm_constant_power_paged()` emitted a debug subpage `ButtonRequest` without clearing the previous page's `button_request_acked`, so debug approval could advance before the new ack and poison the next ceremony. Firmware clears it per new request; companion commit `98c717f` asserts reset/wipe responses and no reply before each backup ack. Pre-fix regression failed; fixed image passed original test 400/400 and regression 20/20. Exact full and bitcoin-only Docker entrypoints and both ARM/SRAM gates passed; hosted run 35799306854 passed on `506ea3e12`. |
| 017 | Copilot P1 `4077885685`: repeated `kkemu_init()` relinked static timer and animation nodes into cycles. Reset both queues and scrub callback state before repopulating. Both new board regressions hang in the respective pre-fix Docker images and pass after; pinned-toolchain dylib first reproduced the animation hang, then passed three init/poll/shutdown cycles. Both ARM/SRAM gates pass. |
| 018 | Copilot P1 `4077885724`: dice evidence requested mutually exclusive `display_random` and `dice_entropy` and expected a forbidden post-mix screen. Use the dice-compatible request and assert direct `EntropyRequest`; the fixed script completed a real Docker reset and saved five screens. |
