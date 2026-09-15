# Exact-head changed-file inventory — 2026-09-14

This inventory reconciles every current PR path to the independent whole-head
runtime/non-runtime reads, the later focused auto-lock review, or the Solana
fee-cap before/after test. Paths assigned to the earlier whole-head reviews did
not change after those review checkpoints. The post-checkpoint diffs contain
only the explicitly assigned auto-lock and Solana paths below. No current path
is left without a named coverage source. This is an audit-coverage receipt, not
a release approval or a claim that inherited deferred risks are fixed.

## #755: 0f64f80323 → 696abece09
65 changed paths; 19 paths changed after the earlier whole-head review at `225eb80fdd`.

| Path | Coverage assignment |
| --- | --- |
| `.github/workflows/ci.yml` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `.github/workflows/release.yml` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `.gitmodules` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `deps/python-keepkey` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `docs/DiceEntropy.md` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `docs/dice-vs-coldcard.md` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `docs/release/7.14.3-COMBINED-CANDIDATE.md` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `docs/release/audit-units/autolock-workflow-progress.md` | focused auto-lock diff + earlier whole-head context |
| `docs/release/audit-units/copilot-followup-20260913.md` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `docs/release/audit-units/full-diff-audit-20260912.md` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `docs/release/audit-units/nonruntime-followup-20260913.md` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `docs/release/audit-units/scope-repair.md` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `docs/security/7.14.3-bitcoin-only-dice-audit-sop.md` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/board/keepkey_board.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/board/layout.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/board/memory.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/board/usb.h` | focused auto-lock diff + earlier whole-head context |
| `include/keepkey/firmware/ethereum_contracts/thortx.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/firmware/fsm.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/firmware/home_sm.h` | focused auto-lock diff + earlier whole-head context |
| `include/keepkey/firmware/mayachain.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/firmware/recovery_cipher.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/firmware/reset.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/firmware/ripple.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/firmware/tiny-json.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/rand/rng_health.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/board/confirm_sm.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/board/keepkey_flash.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/board/layout.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/board/memory.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/board/usb.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/ethereum.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/ethereum_contracts/thortx.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/fsm.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_binance.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_common.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/fsm_msg_cosmos.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_eos.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_ethereum.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/fsm_msg_mayachain.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_osmosis.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_tendermint.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_thorchain.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/home_sm.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/mayachain.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/recovery_cipher.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/reset.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/ripple.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/signing.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/solana.c` | focused Solana fee-cap red/green test + earlier whole-head context |
| `lib/firmware/storage.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/tiny-json.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/rand/rng_health.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `scripts/emulator/capture-dice-flow.py` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `tools/firmware/keepkey.ld` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/board/board.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/confirm_test_utils.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/ethereum.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/fsm.cpp` | focused auto-lock diff + earlier whole-head context |
| `unittests/firmware/mayachain.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/recovery.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/ripple.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/rng_health.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/solana.cpp` | focused Solana fee-cap red/green test + earlier whole-head context |
| `unittests/firmware/storage_passphrase.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |

## #756: 06b1d249ad → 5dd031e49b
87 changed paths; 21 paths changed after the earlier whole-head review at `be9db9c498`.

| Path | Coverage assignment |
| --- | --- |
| `.github/workflows/ci.yml` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `.gitmodules` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `deps/python-keepkey` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `docs/DiceEntropy.md` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `docs/dice-vs-coldcard.md` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `docs/release/7.15-COMBINED-CANDIDATE.md` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `docs/release/audit-units/autolock-workflow-progress.md` | focused auto-lock diff + earlier whole-head context |
| `docs/release/audit-units/copilot-followup-20260913.md` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `docs/release/audit-units/full-diff-audit-20260912.md` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `docs/release/audit-units/nonruntime-followup-20260913.md` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `docs/release/audit-units/scope-repair.md` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `docs/security/clearsign-provider-tier.md` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/board/keepkey_board.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/board/memory.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/board/usb.h` | focused auto-lock diff + earlier whole-head context |
| `include/keepkey/firmware/fsm.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/firmware/hive.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/firmware/home_sm.h` | focused auto-lock diff + earlier whole-head context |
| `include/keepkey/firmware/mayachain.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/firmware/recovery_cipher.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/firmware/ripple.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/firmware/solana.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/rand/rng_health.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `include/keepkey/transport/messages-hive.options` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/board/confirm_sm.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/board/keepkey_flash.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/board/memory.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/board/usb.c` | focused auto-lock diff + earlier whole-head context |
| `lib/emulator/libkkemu.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/authenticator.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/eip712.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/ethereum.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/ethereum_contracts/thortx.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/ethereum_contracts/zxappliquid.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/fsm.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_binance.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_bip85.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/fsm_msg_common.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/fsm_msg_cosmos.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_eos.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_ethereum.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/fsm_msg_hive.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/fsm_msg_mayachain.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_osmosis.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_solana.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/fsm_msg_tendermint.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_thorchain.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/fsm_msg_zcash.h` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/hive.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/home_sm.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/mayachain.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/recovery_cipher.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/reset.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/ripple.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/signed_metadata.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/signing.c` | focused auto-lock diff + earlier whole-head context |
| `lib/firmware/solana.c` | focused Solana fee-cap red/green test + earlier whole-head context |
| `lib/firmware/solana_token_confirm.h` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/storage.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/firmware/thorchain.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `lib/rand/rng_health.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `scripts/emulator/capture-dice-flow.py` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `scripts/generate-test-report.py` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `tools/merge_direction_gate.py` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `tools/merge_symbol_gate.py` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `tools/test_merge_direction_gate.py` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/CMakeLists.txt` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/board/board.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/emulator/CMakeLists.txt` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/emulator/wedged_poll.c` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/CMakeLists.txt` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/authenticator.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/eip712.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/ethereum.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/fsm.cpp` | focused auto-lock diff + earlier whole-head context |
| `unittests/firmware/hive.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/mayachain.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/nanopb_bounds.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/recovery.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/ripple.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/rng_health.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/signed_metadata.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/signing.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/solana.cpp` | focused Solana fee-cap red/green test + earlier whole-head context |
| `unittests/firmware/solana_token_confirm.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/storage_passphrase.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |
| `unittests/firmware/thorchain.cpp` | covered by whole-head runtime/non-runtime audits; unchanged after checkpoint |

The focused auto-lock diff was independently reviewed against accepted
workflow progress and has its own native regressions and exact-head CI. The
Solana explicit-limit fix has a failure-before/pass-after native regression.
This table links those receipts; it does not replace them.

## Exact-head and dependency reconciliation

- #755 head `696abece09f9c00b828f585280bbeff59b657693`: non-publishing CI
  [34915987859](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34915987859)
  passed its aggregate gate, release-evidence gate, full/bitcoin-only ARM and
  emulator builds, native suites, and host integration.
- #756 head `5dd031e49b4bd78948a9d8e52389f81b526a35f6`: non-publishing CI
  [34915989436](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34915989436)
  passed its aggregate gate, full/bitcoin-only ARM and emulator builds, native
  suites, and host integration.
- keepkey/python-keepkey#197 head
  `b76ee610dd18934ee3aeeb36cfc541e8799eb46d` is open, mergeable, and green for
  the 7.14.3 and 7.15 integration matrices. Both firmware candidates now pin that exact head. Canonical merge and re-pin remain
  an upstream integration gate; they are not an unresolved firmware-code audit
  finding.

## Candidate-specific storage regression check

The prior code-identical full and bitcoin-only firmware JUnit artifacts contain passing
regressions for `FreshWalletSurvivesCommitAndReload`, final-secret-byte
corruption retry, marker write failure, marker readback failure, transient
marker recovery, and a valid zero CRC record. Counts were read from artifacts
`10368770395`/`10368392593` for #755 and
`10368462978`/`10369186070` for #756. Source comparison against published
`v7.14.1` confirms that both candidates retain the same erase/rotate ordering.
Their candidate changes add record validation and fail-closed marker handling;
the focused tests establish ordinary success and candidate-specific fault
behavior. They do not prove safety after a physical cut or persistent flash
fault. Those inherited consequences remain open, owner-deferred 7.17 design
work under `storage-baseline-disposition-20260914.md`.

## Remaining release evidence

Application-only unsigned images from the exact CI runs booted on the disposable
physical device, and direct 7.14.3 Bitcoin message signing returned a 65-byte
signature. The operator observations did not unambiguously bind the intended
message text to the OLED on either version. A short physical sign/display smoke
per version remains a release gate. It does not leave a changed source path
unreviewed for the pre-Copilot code audit.
