# 7.15 block 00a — release-foundation receipt

Status: `LOCAL-QUALIFIED`; clean-checkout reproduction and publication pending. Old `ACCEPTED` applies to `f099dfcd8`, not PR #844 head `8e49807a3`.

- Adjacent base: `fc1e93746132553ad98ed60f4847c8d770732bf9`.
- Companion: `c1b136a751038064c29bdf4c25d5a9bf5f8ca8aa` (canonical ancestry); nested device-protocol: `dd9c85dc747cf965fb0e7bf49615dc9e7568ee65`; consumed pins reproduced cleanly.
- Direct device-protocol: `8545cd5b615f5832374afbf06387a3f28869285e`; Trezor crypto: `e8ce42f873dbdae16017122bb4fe8a949f825fc0` ([dependency PR #12](https://github.com/keepkey/trezor-firmware/pull/12)); inactive vendor/test trees excluded.

This foundation carries 7.14.x signing/storage/display/recovery/entropy/authorization hardening and both product build/report/SRAM/artifact gates; later ERC-7730/runtime-provider/chain features are excluded. Signed data is disclosed or refused, aborts clear state, invalid storage cannot partly mutate, and entropy/signature verification fails closed.

## Qualification ledger

| Gate | Historical evidence | Current candidate |
| --- | --- | --- |
| Native Docker | 193 regular / 93 bitcoin firmware, 16 board, 19 crypto pass | 194 regular / 92 bitcoin firmware, 18 board, 19 crypto pass; OTP and Nano regressions included |
| Companion integration | 559 pass/272 skip regular; 334 pass/497 skip bitcoin-only | 559/272 regular and 334/497 bitcoin-only pass/skip |
| Strict OLED | 64 pass/23 skip regular; 25 pass/62 skip bitcoin-only | 64/23 regular and 25/62 bitcoin-only pass/skip |
| ARM/SRAM | Both pass; 21,312/28,268 B reserves; largest frame 12,416 B | Both pass; same reserves and 12,416 B largest frame |
| Static/provenance | Cppcheck 109 files/0 findings; actionlint, format, secret, clean pin and failure probes pass | Cppcheck 109/0; actionlint, format, secret, diff and compose pass; clean pin pending |
| Hosted | [Old head](https://github.com/BitHighlander/keepkey-firmware/actions/runs/35629160260); [current PR head](https://github.com/BitHighlander/keepkey-firmware/actions/runs/35782012448) green | No current-candidate run; at most one after local freeze |

Reviewed skips use `KK_RELEASE_MISSING_CAPABILITIES` or product/version gates; dylib/registry have separate gates, PIN-timeout/empty burned-version have alternate coverage, and seven Osmosis plus five boot/upgrade tests run in both profiles. Flaky retries do not count.

## Findings and closure evidence

Owner: BitHighlander release; local reviewer: Codex. Findings 001–012 affect `f099dfcd8`, 013–015 affect `8e49807a3`; 001/003/005 are operational, 006 decoder-integrity, 013 policy, and the others high/release-blocking. Review threads and the gate ledger supply verification.

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
