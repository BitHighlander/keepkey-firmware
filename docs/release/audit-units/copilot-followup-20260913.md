# PR 756 runtime audit/disposition

Actual base: `06b1d249ada75b53d06cb5b7f27512fd276ef83c` (`audit/715-p03-pending-version-lock`).
Audited candidate: `4921cf913521aa5128f3818828cd049f34b90f49`.
Local corrective commit: `4aec28fca05b67018ad2aca105387db361c81085`.
The runtime fix was incorporated into follow-up PR #763. No review thread was resolved and no new Copilot review was requested.

Reviewed all 53 changed include/lib/runtime-test files listed below against the actual base, plus tools/merge_direction_gate.py. Adjacent call paths inspected for reachability. Other scripts, docs, .github, pins and PR claims belong to the separate integrator coverage pass; this runtime report alone is not a whole-candidate audit.

| Finding | Evidence / disposition | Verification |
| --- | --- | --- |
| Copilot 4001505609 P2: MAYA mixed deposit separator | Confirmed. MsgSend sets has_message; old deposit prelude never emits comma. Added separator at lib/firmware/mayachain.c:262. | MixedSendDepositIsCommaSeparatedInTheSignedDocument reconstructs canonical JSON and expected ECDSA signature. Fails old HEAD, passes fix. |
| Copilot 4001505636 and 4001505653 P1: schema unit price | Confirmed one issue, including unsafe regression. Removed UNIT_PRICE from schema companion allowlist (lib/firmware/solana.c:890). Opaque/schema path has no fee screen; unsupported schema follows existing explicit AdvancedMode blind-sign flow. | SchemaRejectsUndisclosedComputeUnitPrice fails old HEAD. Same two-instruction tx with limit-only companion remains applicable. |
| Copilot 4001505690 P2: recipient helper scope comment | Confirmed stale comment. fsm_msg_solana.h:730 calls recipient-owner derivation; known-token helper remains unit-only. Corrected unit-test commentary. | Read call graph and all Solana tests. |
| Copilot body P1: narrow pager zero progress | REFUTED for stated BIP39 trigger. layout.c:366/392 already wraps at 124 px. Reset/BIP85 emit TWO numbered words before newline; a row wraps to at most two physical rows, so a fitting row prefix exists. | EveryBip39WordPairFitsANarrowSubpage exhaustively checks all 4,194,304 word pairs with two-digit numbers against actual fit probe and pager, 46.996 seconds, PASS without runtime modification. |
| Copilot body P2: chain ID rejected after domain screen | REFUTED claimed order. confirmTypedValue marshals domain values; parseVals strtoll rejects >INT64_MAX at line 825 before dsConfirm at line 1010. Encoder supports signed 64-bit maximum, not full uint64. Corrected misleading comments only. | DomainRejectsChainIdAboveEncoderRangeBeforeConsent passes both original and final code; queued cancellation remains untouched for 9223372036854775808 and 18446744073709551615. This pins existing behavior, is not a fix test. |
| Copilot body P2: budget instructions excluded from SIMD-0170 default | REFUTED. Agave second pass iterates all instructions to count builtin/nonbuiltin programs. Its unit-price fixture explicitly expects one non-migratable builtin. Keep 203k upper-bound calculation for token+price. | Primary source pinned https://github.com/anza-xyz/agave/blob/8fe3f1201abc5b0244540aed0c7bf8c6bcafb3f5/compute-budget-instruction/src/compute_budget_instruction_details.rs lines 65-88, 180-201, 289-300. Existing native priority fee tests pass. |
| Copilot body: merge gate suppresses repository read failures (P2) | Confirmed. First query ls-tree; only absent entry returns None. Existing entry requires successful git show. | Four disposable-git tests: present, absent, invalid revision, physically deleted blob object. Old gate fails missing-object/revision tests; fixed gate passes all. |
| NEW P2: timed-out emulator stop leaves unsafe public entry points | Candidate libkkemu.c:566 sets g_poll_wedged but clears running flag before writer exits. Old kkemu_poll can run a second core; trylock incorrectly succeeds without mutex; blocking lock skips mutex; get_display reads live canvas. Guard poll/display and trylock, preserve mutex use for blocking lock/unlock while wedged. | Standalone emulator-wedge-unit includes real implementation and injects exact timeout state. Old HEAD aborts on trylock assertion; fixed target passes poll/start/display/mutex checks. No live wallet/thread/UDP needed. |

Verification of final source tree:
- Native Mac Debug emulator full firmware-unit: 540/540 passed, 31.541 s (`/tmp/715-full-unit.log`).
- board-unit: 16/16 passed, 2.564 s, excluding separately completed exhaustive row test (`/tmp/715-full-board.log`).
- exhaustive BIP39 pair test: 1/1 passed, 46.996 s (`/tmp/715-pager.log`).
- python3 tools/test_merge_direction_gate.py: 4/4 passed (`/tmp/715-gate-after.log`).
- cmake --build build-copilot --target emulator-wedge-unit -j 8; build-copilot/bin/emulator-wedge-unit: passed.
- Before controls: `/tmp/715-before.log`, `/tmp/715-gate-before.log`; old wedge harness exited -6 on failed trylock assertion.
- git diff --check passed. Tests ran against the final code tree before the local commit, with the separately added wedge target built afterward; these are local source tests, not exact-head hosted CI certification.

Native setup: `PATH=/private/tmp/kk-copilot-bin:/private/tmp/kk-nanopb-0.3.9.4/generator:$PATH`; CMake Debug, KK_DEBUG_LINK=ON, KK_EMULATOR=ON, PB_NO_PACKED_STRUCTS=1 C/CXX flags, macOS -Wl,-no_fixup_chains, NANOPB_DIR=/private/tmp/kk-nanopb-0.3.9.4, protoc=/opt/homebrew/opt/protobuf@21/bin/protoc. Top-level and nested Ethereum submodules initialized at candidate pins. build-copilot/ remains untracked.

Open release gates / constraints:
- Scope-repair intentionally withdraws storage durability/pending-record changes. Erase-before-replacement interruption remains OPEN, explicitly deferred under owner correction (docs/release/audit-units/scope-repair.md), not fixed/waived here.
- Hosted exact-head CI, ARM, Bitcoin-only, pinned host integration and physical OLED/device tests not performed by this bounded runtime pass. Root owns candidate gate and reporting.
- Emulator-wedge-unit covers public API guard behavior by injected post-timeout state; it does not simulate a physical thread timing out, nor fix any underlying timer wedge.
- No other actionable finding identified in assigned runtime/test changes. No claim that the entire candidate is clean while separate gates or deferred blockers remain.

## Exact candidate file coverage

- `include/keepkey/board/keepkey_board.h`
- `include/keepkey/board/memory.h`
- `include/keepkey/firmware/fsm.h`
- `include/keepkey/firmware/hive.h`
- `include/keepkey/firmware/home_sm.h`
- `include/keepkey/firmware/mayachain.h`
- `include/keepkey/firmware/ripple.h`
- `include/keepkey/transport/messages-hive.options`
- `lib/board/confirm_sm.c`
- `lib/board/keepkey_flash.c`
- `lib/board/memory.c`
- `lib/emulator/libkkemu.c`
- `lib/firmware/authenticator.c`
- `lib/firmware/eip712.c`
- `lib/firmware/ethereum.c`
- `lib/firmware/ethereum_contracts/thortx.c`
- `lib/firmware/ethereum_contracts/zxappliquid.c`
- `lib/firmware/fsm.c`
- `lib/firmware/fsm_msg_bip85.h`
- `lib/firmware/fsm_msg_common.h`
- `lib/firmware/fsm_msg_ethereum.h`
- `lib/firmware/fsm_msg_hive.h`
- `lib/firmware/fsm_msg_mayachain.h`
- `lib/firmware/fsm_msg_solana.h`
- `lib/firmware/fsm_msg_thorchain.h`
- `lib/firmware/fsm_msg_zcash.h`
- `lib/firmware/hive.c`
- `lib/firmware/home_sm.c`
- `lib/firmware/mayachain.c`
- `lib/firmware/recovery_cipher.c`
- `lib/firmware/reset.c`
- `lib/firmware/ripple.c`
- `lib/firmware/signed_metadata.c`
- `lib/firmware/signing.c`
- `lib/firmware/solana.c`
- `lib/firmware/storage.c`
- `lib/firmware/thorchain.c`
- `lib/rand/rng_health.c`
- `unittests/board/board.cpp`
- `unittests/firmware/authenticator.cpp`
- `unittests/firmware/eip712.cpp`
- `unittests/firmware/ethereum.cpp`
- `unittests/firmware/fsm.cpp`
- `unittests/firmware/hive.cpp`
- `unittests/firmware/mayachain.cpp`
- `unittests/firmware/nanopb_bounds.cpp`
- `unittests/firmware/recovery.cpp`
- `unittests/firmware/ripple.cpp`
- `unittests/firmware/signed_metadata.cpp`
- `unittests/firmware/signing.cpp`
- `unittests/firmware/solana.cpp`
- `unittests/firmware/storage_passphrase.cpp`
- `unittests/firmware/thorchain.cpp`

## Integrator coverage status

Independent storage verification found that a persistent failed boot-protection
marker still causes the installed bootloader to erase all storage on reboot.
The 7.15 carry-forward now accepts a valid CRC32 of zero, verifies marker
readback, retries transient marker faults, and refuses to report Success on
exhausted retries. The full native firmware suite passes 548/548, including
six focused commit/reload and fault-injection regressions. The RNG boot gate
also checks the hardware fault mirror after each sampled draw; a mid-sample
fault regression passes. These are fixes to the 7.15 line itself, not an
assumption that 7.14.3 coverage transfers.

Persistent marker failure remains a separate OPEN release blocker from the
erase-before-replacement power-loss P1. The exit tests prove only that an active
record exists before shutdown; the installed bootloader's protection check
still erases all sectors when the marker remains invalid. Neither candidate is
release-ready.

The integrator corrected the release receipt, Python-host PR URL, and dice screenshot numbering, and checked workflow YAML syntax, Python syntax, and the merge-symbol gate. Remaining metadata, report-generator, host-pin, and PR-description assertions require final evidence reconciliation on the eventual candidate head. A new Copilot review is blocked until this coverage and exact-head CI are complete.
