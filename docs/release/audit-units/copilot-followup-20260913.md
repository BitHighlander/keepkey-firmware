# 7.14.3 bounded runtime Astra audit and disposition

PR: BitHighlander/keepkey-firmware #755.
Actual base: audit/7143-p03-pending-version-lock, `0f64f80323813e107c25b838d137cc0e65417d79`.
Frozen reviewed head: `18606c1a04b6740142b7313a59f47596542eec79`.
Working repair parent: `d00ed3103f7fdb07bb3948be3f677d4789190f85` (PR #762).
Repair commit: `de806704312b0ef00a38ad21d1839343fe16be9b`, included in follow-up PR #762. No review thread was resolved and no new Copilot review was requested.
SOP: `docs/release/ASTRA-AUDIT-SOP.md` in follow-up PR #761.

This is a bounded runtime/runtime-test audit, not release approval. Read all 39 assigned changed files against actual base/head and adjacent call paths; no assigned coverage gap. Root owns CI, scripts, dependency-pin and documentation evidence. Exact-head CI/hardware acceptance is not established by these local tests.

## Dispositions

| Finding | Trigger / consequence / proof | Disposition and verification |
| --- | --- | --- |
| Copilot 4001507735 P1 fresh magic | Fresh RAM metadata is serialized before `stor` is stamped at frozen head storage.c ~1655; reboot cannot select that committed sector. | Already fixed by PR #762 parent d00ed3103. Read changed code and ran FreshWalletSurvivesCommitAndReload and full suite. |
| Copilot 4001507746 P2 zero CRC | Frozen-head storage.c treats CRC 0 as unconditional retry and eventually wipes despite valid serialized data. | Already fixed by PR #762 parent. Full commit/reload zero-CRC solver regression passes. |
| Copilot 4001507759 P1 erase-before-replacement | storage.c current line 1671 erases active sector before replacement data, magic and CRC verification. Power cut there leaves no wallet record; memory.c no longer has pending record recovery. | CONFIRMED OPEN. Durability transaction explicitly excluded by this scope repair. Owner: release owner/storage durability workstream. Release-blocking until a separately reviewed migration/bootloader-compatible fix and power-cut hardware evidence. No claim of zero open blockers. |
| Copilot 4001507766 P1 ignored protection marker failure | storage.c frozen-head CRC-success branch discards storage_protect_off false; memory.c only returned flash programming status and did not verify bytes. Caller could answer Success while installed bootloader sees missing marker. | PARTIALLY FIXED: firmware now refuses Success, verifies readback, and retries only the marker sector up to three times. A transient fault recovers; the three marker tests and full 221-case native suite pass. A persistent fault still leaves an invalid marker. The bootloader's storage_protect_wipe(storage_protect_status()) then erases all sectors on reboot. The exit tests prove an active sector exists before shutdown, not boot survival. This separate OPEN release blocker requires bootloader-compatible recovery. |
| Copilot 4001507777 P2 boot gate latch | rng_health_gate frozen-head loop folds random_buffer chunks without checking mid-draw fault mirror. Source may statistically pass, caching RNG_PASSED once despite observed hardware fault. | FIXED: check mirror after every gate chunk before health update, wipe chunk/context on failure. FaultDuringBootSampleFailsClosed control returned true and sampled 1024; fixed returns false after 32 bytes. Post-checked-draw injection also asserts output wipe. |
| Review body THOR amount P2 | Router classification tests do not exercise native deposit display; ABI amount can differ from signed msg.value. | FIXED coverage. NativeThorConfirmationDisplaysValueInsteadOfAbiAmount enters thor_confirmThorTx with 1 ETH ABI and 2 ETH msg.value, accepts router/vault, inspects actual amount screen at confirm_screen boundary. Control using ABI Amount displays 1 ETH and fails. Native behavior itself was correct at frozen head. |
| Review body FSM callback P2 | note_host_activity direct tests miss registration/order regressions. | FIXED coverage. Emulator receive seam delivers partial Ping through current registered callback after fsm_init; a stalled stream survives two partial intervals, home polling still locks. Test clears partial frame afterward. Control registering board handler instead of FSM wrapper fails active-stream assertion. |
| Review body Ethereum node wipe P3 | process_ethereum_xfer recipient mismatch can return after deriving shared private-key scratch. | FIXED coverage. Full FSM handler uses initialized mnemonic, known USDC transfer and zero ABI recipient proven unequal to derived path recipient. Approval budget proves transfer screen reached; scratch-zero assertion fails with mismatch wipe removed. Pubkey-hash derivation-failure branch not fault-injected; valid secp256k1 derivation does not offer a deterministic natural failure. Code was read and preserves its wipe. |
| Review body recovery terminating separator P2 | Claimed 13 separators necessary. | REFUTED: recovery_cipher_init line 325 sets words_entered=1; separator 12 enters finalize at line 484. Strengthened test asserts still armed after 11, then consumes separator 12. Control removing words_committed guard actually stores empty seed and fails. Separately FIXED fixture independence: storage_wipe erases flash but leaves RAM shadow; added storage_reset before initial uninitialized assertion. |
| Review body CRC coverage P2 | Board local buffer test cannot observe storage_commit word count. | FIXED coverage. Fault hook corrupts actual programmed byte 2568 once and counts payload writes. Current commit detects and retries (2 writes); control with both CRC word counts set to 642 returns after 1 write, fails assertion and then reaches storage decrypt assertion on reload. Production buffer assertions remain. |
| Review body RNG source-order P3 | Process-global verdict makes boot test skip real gate under reordered tests. | FIXED emulator-only reset seam; fresh gate fixture resets before each test and records exactly RNG_HEALTH_SAMPLE_BYTES sampled once. RNG suite passed 10 shuffled runs, 20 tests each. Also cleaned up transient-latch fixture so shuffled subsequent tests are independent. |
| Review body stale THOR symbol P3 | Header references nonexistent thor_router_for_chain. | FIXED comment to thor_router_label. |
| Additional metadata comment P3 | Restored Metadata removes generation but header incorrectly places Storage at 0x29. Serialization and ConfigFlash actually retain 3 bytes alignment padding and storage at 0x2c. | FIXED layout comment only. Runtime fixed-offset serialization unchanged. |

## Wider runtime review

Storage: read active selection, removed framing/pending APIs, metadata serialization and version lock, wear-level rotation, commit failure paths, session-clear callers and setup authorization. Preserve the known durability blocker above; no restoration of V17 generation/trailer scheme in this batch.
Signing/crypto: read THOR classification/ABI bounds/amount selection, Ethereum transfer formatting and scratch exits, multisig 73-byte protobuf signature copy plus separate sighash byte, MAYA denom rendering call sites, XRP bound/serializer, Solana bounded instruction parser and overflow-safe fee calculation, recovery finalize and seed setup staging.
Transport/display: read receive wrapper ordering, home state/idle reset, session revoke and transport rejection behavior, bitcoin-only mutation guards, confirm scratch cleanup and debug watermark callers. Test-only hooks are EMULATOR-guarded and do not enter hardware binaries.
Build/memory: read 16 KiB SRAM linker ASSERT and board metadata offsets; actual ARM stack/variant gates remain separate.

## Assigned frozen-diff coverage (39 files)

- `include/keepkey/board/keepkey_board.h`
- `include/keepkey/board/layout.h`
- `include/keepkey/board/memory.h`
- `include/keepkey/firmware/ethereum_contracts/thortx.h`
- `include/keepkey/firmware/fsm.h`
- `include/keepkey/firmware/home_sm.h`
- `include/keepkey/firmware/mayachain.h`
- `include/keepkey/firmware/reset.h`
- `include/keepkey/firmware/ripple.h`
- `include/keepkey/firmware/tiny-json.h`
- `lib/board/confirm_sm.c`
- `lib/board/keepkey_flash.c`
- `lib/board/layout.c`
- `lib/board/memory.c`
- `lib/firmware/ethereum.c`
- `lib/firmware/ethereum_contracts/thortx.c`
- `lib/firmware/fsm.c`
- `lib/firmware/fsm_msg_common.h`
- `lib/firmware/fsm_msg_ethereum.h`
- `lib/firmware/home_sm.c`
- `lib/firmware/mayachain.c`
- `lib/firmware/recovery_cipher.c`
- `lib/firmware/reset.c`
- `lib/firmware/ripple.c`
- `lib/firmware/signing.c`
- `lib/firmware/solana.c`
- `lib/firmware/storage.c`
- `lib/firmware/tiny-json.c`
- `lib/rand/rng_health.c`
- `tools/firmware/keepkey.ld`
- `unittests/board/board.cpp`
- `unittests/firmware/ethereum.cpp`
- `unittests/firmware/fsm.cpp`
- `unittests/firmware/mayachain.cpp`
- `unittests/firmware/recovery.cpp`
- `unittests/firmware/ripple.cpp`
- `unittests/firmware/rng_health.cpp`
- `unittests/firmware/solana.cpp`
- `unittests/firmware/storage_passphrase.cpp`

Additional repair/seam files read: include/keepkey/board/usb.h, include/keepkey/rand/rng_health.h, lib/board/usb.c, unittests/firmware/confirm_test_utils.cpp. Adjacent paths include lib/board/messages.c, lib/rand/rng.c, lib/firmware/coins.c, fsm_msg_mayachain.h, fsm_msg_ripple.h, and storage/passphrase initialization.

## Verification

Working directory: /private/tmp/kk-7143-copilot.
- `cmake --build build-copilot --target firmware-unit board-unit -j 8` PASS. Local native Debug, KK_EMULATOR=ON, KK_DEBUG_LINK=ON, KK_BITCOIN_ONLY=OFF; host protobuf 21, nanopb 0.3.9.4, PB_NO_PACKED_STRUCTS=1.
- `build-copilot/bin/firmware-unit` PASS 220/220 after all fixes/control restoration; /private/tmp/kk7143-runtime-final.log.
- `build-copilot/bin/board-unit` PASS 19/19; /private/tmp/kk7143-runtime-board.log.
- `build-copilot/bin/firmware-unit --gtest_filter='RngBootGate.*:RngHealth.*' --gtest_shuffle --gtest_repeat=10` PASS 20/20 ten times; /private/tmp/kk7143-rng-shuffled.log.
- Before/after controls: /private/tmp/kk7143-runtime-control-noninteractive.log (RNG + two marker tests all fail under reverted guards), /private/tmp/kk7143-runtime-control-interactive.log (callback/Ethereum wipe/recovery/THOR all fail, home control stays green), /private/tmp/kk7143-runtime-control-crc.log (retry-count failure then expected decryption assertion). Control files restored from /private/tmp/kk7143-runtime-control-backup.json before final build. Control-corrupted test image preserved as /private/tmp/kk7143-control-corrupt-emulator.img; final suite starts from a fresh ephemeral emulator image.
- `git diff --check` PASS. `git clang-format --force HEAD` formatted only changed lines with local clang-format 22.1.1; CI's pinned clang-format 20 full-file check still needs its own run.
- Fresh Bitcoin-only native configure/build attempted at /private/tmp/kk7143-btc-runtime. Configuration passed after CMAKE_POLICY_VERSION_MINIMUM=3.5 and explicit local generator path. Build STOPPED at existing nanopb options lookup: `Options file not found:  messages*.options`, generated `pb_callback_t forbidden`. Logs: /private/tmp/kk7143-btc-runtime-configure.log and /private/tmp/kk7143-btc-runtime-build.log. This is an open local variant validation gap, not a passed variant gate.
- Not run: ARM builds, physical RNG/power-cut/hardware/screen checks, Python host integration, exact-new-head CI. Root must preserve these gaps in combined ledger.

## Integrator coverage status

The integrator corrected the Compose build gate, release receipt, submodule attribution, scope statement and dice screenshot numbering. Workflow YAML and Python syntax passed locally. Remaining metadata, dependency-pin and PR-description claims require final reconciliation at the eventual candidate head. A new Copilot review is blocked until this coverage and exact-head CI are complete.
