# Exact-head changed-file inventory — 2026-09-14

This is a reconciliation inventory, **not a clean audit certification**.
It maps each current PR path to the earlier whole-head read, the later focused
auto-lock review, or the Solana fee-cap before/after test. The earlier
whole-head reports inventoried all files
but did not establish a current-head non-runtime claim review for every row.
The final Copilot gate remains open until those gaps, hardware screens and
candidate-specific storage non-regression are dispositioned.

## #755: 0f64f80323 → 4125e1c740
65 changed paths; 19 paths changed after the earlier whole-head review at `225eb80fdd`.

| Path | Coverage assignment |
| --- | --- |
| `.github/workflows/ci.yml` | earlier whole-head inventory; confirm current claim/evidence |
| `.github/workflows/release.yml` | earlier whole-head inventory; confirm current claim/evidence |
| `.gitmodules` | earlier whole-head inventory; confirm current claim/evidence |
| `deps/python-keepkey` | earlier whole-head inventory; confirm current claim/evidence |
| `docs/DiceEntropy.md` | earlier whole-head inventory; confirm current claim/evidence |
| `docs/dice-vs-coldcard.md` | earlier whole-head inventory; confirm current claim/evidence |
| `docs/release/7.14.3-COMBINED-CANDIDATE.md` | earlier whole-head inventory; confirm current claim/evidence |
| `docs/release/audit-units/autolock-workflow-progress.md` | focused auto-lock diff + earlier whole-head context |
| `docs/release/audit-units/copilot-followup-20260913.md` | earlier whole-head inventory; confirm current claim/evidence |
| `docs/release/audit-units/full-diff-audit-20260912.md` | earlier whole-head inventory; confirm current claim/evidence |
| `docs/release/audit-units/nonruntime-followup-20260913.md` | earlier whole-head inventory; confirm current claim/evidence |
| `docs/release/audit-units/scope-repair.md` | earlier whole-head inventory; confirm current claim/evidence |
| `docs/security/7.14.3-bitcoin-only-dice-audit-sop.md` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/board/keepkey_board.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/board/layout.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/board/memory.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/board/usb.h` | focused auto-lock diff + earlier whole-head context |
| `include/keepkey/firmware/ethereum_contracts/thortx.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/firmware/fsm.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/firmware/home_sm.h` | focused auto-lock diff + earlier whole-head context |
| `include/keepkey/firmware/mayachain.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/firmware/recovery_cipher.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/firmware/reset.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/firmware/ripple.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/firmware/tiny-json.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/rand/rng_health.h` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/board/confirm_sm.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/board/keepkey_flash.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/board/layout.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/board/memory.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/board/usb.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/ethereum.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/ethereum_contracts/thortx.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/fsm.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_binance.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_common.h` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/fsm_msg_cosmos.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_eos.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_ethereum.h` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/fsm_msg_mayachain.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_osmosis.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_tendermint.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_thorchain.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/home_sm.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/mayachain.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/recovery_cipher.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/reset.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/ripple.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/signing.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/solana.c` | focused Solana fee-cap red/green test + earlier whole-head context |
| `lib/firmware/storage.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/tiny-json.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/rand/rng_health.c` | earlier whole-head inventory; confirm current claim/evidence |
| `scripts/emulator/capture-dice-flow.py` | earlier whole-head inventory; confirm current claim/evidence |
| `tools/firmware/keepkey.ld` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/board/board.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/confirm_test_utils.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/ethereum.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/fsm.cpp` | focused auto-lock diff + earlier whole-head context |
| `unittests/firmware/mayachain.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/recovery.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/ripple.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/rng_health.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/solana.cpp` | focused Solana fee-cap red/green test + earlier whole-head context |
| `unittests/firmware/storage_passphrase.cpp` | earlier whole-head inventory; confirm current claim/evidence |

## #756: 06b1d249ad → d33f1711c3
87 changed paths; 21 paths changed after the earlier whole-head review at `be9db9c498`.

| Path | Coverage assignment |
| --- | --- |
| `.github/workflows/ci.yml` | earlier whole-head inventory; confirm current claim/evidence |
| `.gitmodules` | earlier whole-head inventory; confirm current claim/evidence |
| `deps/python-keepkey` | earlier whole-head inventory; confirm current claim/evidence |
| `docs/DiceEntropy.md` | earlier whole-head inventory; confirm current claim/evidence |
| `docs/dice-vs-coldcard.md` | earlier whole-head inventory; confirm current claim/evidence |
| `docs/release/7.15-COMBINED-CANDIDATE.md` | earlier whole-head inventory; confirm current claim/evidence |
| `docs/release/audit-units/autolock-workflow-progress.md` | focused auto-lock diff + earlier whole-head context |
| `docs/release/audit-units/copilot-followup-20260913.md` | earlier whole-head inventory; confirm current claim/evidence |
| `docs/release/audit-units/full-diff-audit-20260912.md` | earlier whole-head inventory; confirm current claim/evidence |
| `docs/release/audit-units/nonruntime-followup-20260913.md` | earlier whole-head inventory; confirm current claim/evidence |
| `docs/release/audit-units/scope-repair.md` | earlier whole-head inventory; confirm current claim/evidence |
| `docs/security/clearsign-provider-tier.md` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/board/keepkey_board.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/board/memory.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/board/usb.h` | focused auto-lock diff + earlier whole-head context |
| `include/keepkey/firmware/fsm.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/firmware/hive.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/firmware/home_sm.h` | focused auto-lock diff + earlier whole-head context |
| `include/keepkey/firmware/mayachain.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/firmware/recovery_cipher.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/firmware/ripple.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/firmware/solana.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/rand/rng_health.h` | earlier whole-head inventory; confirm current claim/evidence |
| `include/keepkey/transport/messages-hive.options` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/board/confirm_sm.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/board/keepkey_flash.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/board/memory.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/board/usb.c` | focused auto-lock diff + earlier whole-head context |
| `lib/emulator/libkkemu.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/authenticator.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/eip712.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/ethereum.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/ethereum_contracts/thortx.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/ethereum_contracts/zxappliquid.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/fsm.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_binance.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_bip85.h` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/fsm_msg_common.h` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/fsm_msg_cosmos.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_eos.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_ethereum.h` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/fsm_msg_hive.h` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/fsm_msg_mayachain.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_osmosis.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_solana.h` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/fsm_msg_tendermint.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_thorchain.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_zcash.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/hive.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/home_sm.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/mayachain.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/recovery_cipher.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/reset.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/ripple.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/signed_metadata.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/signing.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/solana.c` | focused Solana fee-cap red/green test + earlier whole-head context |
| `lib/firmware/solana_token_confirm.h` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/storage.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/firmware/thorchain.c` | earlier whole-head inventory; confirm current claim/evidence |
| `lib/rand/rng_health.c` | earlier whole-head inventory; confirm current claim/evidence |
| `scripts/emulator/capture-dice-flow.py` | earlier whole-head inventory; confirm current claim/evidence |
| `scripts/generate-test-report.py` | earlier whole-head inventory; confirm current claim/evidence |
| `tools/merge_direction_gate.py` | earlier whole-head inventory; confirm current claim/evidence |
| `tools/merge_symbol_gate.py` | earlier whole-head inventory; confirm current claim/evidence |
| `tools/test_merge_direction_gate.py` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/CMakeLists.txt` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/board/board.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/emulator/CMakeLists.txt` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/emulator/wedged_poll.c` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/CMakeLists.txt` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/authenticator.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/eip712.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/ethereum.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/fsm.cpp` | focused auto-lock diff + earlier whole-head context |
| `unittests/firmware/hive.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/mayachain.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/nanopb_bounds.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/recovery.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/ripple.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/rng_health.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/signed_metadata.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/signing.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/solana.cpp` | focused Solana fee-cap red/green test + earlier whole-head context |
| `unittests/firmware/solana_token_confirm.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/storage_passphrase.cpp` | earlier whole-head inventory; confirm current claim/evidence |
| `unittests/firmware/thorchain.cpp` | earlier whole-head inventory; confirm current claim/evidence |

The focused auto-lock diff was separately reviewed against accepted
workflow progress and has its own native tests and exact-head CI. This table
does not replace its independent reviewer receipt. Host pins still point to
open upstream Python PRs #197/#223; neither is a canonical merged dependency.
No physical KeepKey was visible in the USB inventory when this ledger was made.
