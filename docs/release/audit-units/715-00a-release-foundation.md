# 7.15 block 00a — release-foundation receipt

Publication snapshot: `PUBLISHED` candidate after local Docker qualification, with findings 021–025 from Copilot review 5286105814 addressed or dispositioned. Historical hosted evidence: [run 35807704204](https://github.com/BitHighlander/keepkey-firmware/actions/runs/35807704204) passed on `b643fca9c`; it does not qualify this code head. The exact head/tree, current hosted run and live acceptance verdict belong in a post-push PR attachment, per the SOP.

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
| Static/provenance | Cppcheck 109 files/0 findings; actionlint, format, secret, clean pin and failure probes pass | Cppcheck 109/0 on prior head and changed `layout.c`/`timer.c`/`libkkemu.c` 0 findings; clang-format, actionlint, diff, clean pins and Gitleaks pass on final code head |
| Hosted | [Run 35805082008](https://github.com/BitHighlander/keepkey-firmware/actions/runs/35805082008) passed on `6c7dac7ee` | [Run 35807704204](https://github.com/BitHighlander/keepkey-firmware/actions/runs/35807704204) passed on `b643fca9c`; new code head requires its own exact-head gate |

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
| 019 | Copilot P2 `4078257542`: SignIdentity fingerprint remained on the stack after PIN refusal. Scrub on invalid identity, PIN refusal and immediately after deriving the address path; retain existing PIN failure layout. Requalify exact head. |
| 020 | Copilot P2 `4078257578`: checked-in receipt cited an obsolete hosted verdict. Separate historical green runs from current candidate qualification, which is attached to the PR after push. |
| 021 | Copilot P1 `4078394190`: reject any decoded Ripple memo before PIN/approval; serializer cannot commit it. Live Docker negative probe gets `Ripple memos are not supported`; normal signing passes. |
| 022 | Copilot P1 `4078394229`: reject explicit non-`rune` THORChain sends before approval; serializer hard-codes native RUNE. Live Docker negative probe gets `Only native RUNE sends are supported`; native send passes. |
| 023 | Copilot P2 `4078394255`: remove orphaned DEBUG_LINK bootloader watermark call; the helper was intentionally removed from layout. Docker ARM DEBUG_LINK bootloader compiles and links. |
| 024 | Copilot P1 `4078394274`: decline restoration of transformERC20/MakerDAO specialized dispatch. Existing `TransformErc20AlwaysRequiresAdvancedMode` and `MakerDaoSelectorsAreNotSpecializedForPointRelease` regressions require raw AdvancedMode review because those decoders hide or incompletely validate calldata. |
| 025 | Copilot P1 `4078394302`: suppress `DebugLinkState.reset_entropy` while dice digest marks an active dice ceremony. Live capture asserts it absent at `EntropyRequest`: assertion fails against `b643fca9c` image and passes against fixed image, completing five-screen reset. |
