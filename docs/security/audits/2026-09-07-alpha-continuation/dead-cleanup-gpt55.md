# KeepKey dead-firmware cleanup report — gpt55

Scope: C3-009, C3-024, C3-038, C3-068, C3-076 from `/private/tmp/keepkey-cycle3-recovered.json`. Followed `docs/security/ALPHA-AUDIT-SOP.md` dead-surface rule. No builds, commits, pushes, subagents, or protocol submodule edits.

## Pre-existing dirty files preserved

Before this cleanup, these task-owned files were already dirty and were preserved while editing the current working tree:

- `include/keepkey/firmware/signed_metadata.h`
- `lib/board/memory.c`
- `lib/firmware/osmosis.c`
- `lib/firmware/signed_metadata.c`

`deps/device-protocol` is dirty in the checkout, but this agent did not edit protocol submodules.

## C3-009 — THORChain router fallback / ETH_NATIVE

Evidence: `ETH_NATIVE` had no references outside its define. `thor_confirm_deposit_tx()` is reached only through the Mayachain/Thorchain wrappers after router predicates in `ethereum_contracts.c`, and the wrappers already pass both valid labels.

Changes:

- Removed unused `ETH_NATIVE` from `include/keepkey/firmware/ethereum_contracts/thortx.h`.
- Collapsed the unreachable router recomputation/fallback in `lib/firmware/ethereum_contracts/thortx.c`; the route screen now uses `conf = router_label` at `thortx.c:172`.
- Preserved valid labels: `Thorchain router` and `Maya router`.

## C3-024 — Osmosis dead derivations / stale declarations

Evidence: whole-tree search showed `debug_intermediate_hash()` had no definition or caller. In `Delegate`, `Undelegate`, `Redelegate`, and `Rewards`, `from_address` was derived and never read; remaining live sender-binding derives are still present in MsgSend, LP add/remove, IBC transfer, and Swap.

Changes:

- Removed `debug_intermediate_hash()` from `include/keepkey/firmware/osmosis.h`.
- Removed unused `<time.h>` from `lib/firmware/osmosis.c`.
- Removed unused local `mainnetp/testnetp/pfix/from_address/tendermint_getAddress()` blocks from:
  - `osmosis_signTxUpdateMsgDelegate()` (`osmosis.c:208`)
  - `osmosis_signTxUpdateMsgUndelegate()` (`osmosis.c:263`)
  - `osmosis_signTxUpdateMsgRedelegate()` (`osmosis.c:318`)
  - `osmosis_signTxUpdateMsgRewards()` (`osmosis.c:507`)
- Removed the stale Swap testnet TODO; current Swap code already derives with `testnet ? "tosmo" : "osmo"` (`osmosis.c:655`).

Preserved behavior: staking delegator address remains host-provided, signed, bech32-decoded, and displayed as before. This patch does not add a new signer-address binding for those staking messages.

## C3-038 — TON unused amount formatter

Evidence: `ton_formatAmount()` had only declaration/definition references in firmware and no callers. `ton_formatRawTxDigest()` remains live for blind-sign disclosure.

Changes:

- Removed `ton_formatAmount()` from `lib/firmware/ton.c`.
- Removed its declaration/comment from `include/keepkey/firmware/ton.h`.

Not changed: `TonSignTx` protocol fields and proto comments are in protocol submodules; root explicitly said not to touch protocol submodules in this pass.

## C3-068 — signed metadata runtime signer dead API / dead non-runtime tier path

Evidence: `signed_metadata_signer_is_runtime()` had no callers. `metadata_pubkey_for()` returns a key only from `loaded_pubkeys[]` and sets `is_loaded=true`; therefore the non-runtime `METADATA_TIER_NONE` assignment in the runtime metadata process path was unreachable.

Changes:

- Removed `signed_metadata_signer_is_runtime()` from `include/keepkey/firmware/signed_metadata.h` and `lib/firmware/signed_metadata.c`.
- Made runtime metadata processing require `pubkey && is_loaded && AdvancedMode`, then set `metadata_tier = METADATA_TIER_RUNTIME` directly at `signed_metadata.c:906`.
- Tightened adjacent signer fingerprint/attestation helpers to the same current invariant: key must be loaded and AdvancedMode-enabled before use.

Preserved behavior: certified KeepKey delegate path and runtime AdvancedMode gating remain separate. `METADATA_TIER_NONE` itself remains because it is still used for clear/reset state.

## C3-076 — USART_DEBUG_ON unreachable branch

Evidence: whole-tree search across `lib`, `include`, `unittests`, `CMakeLists.txt`, and `cmake` found no build definition for `USART_DEBUG_ON`; it was only referenced by the guarded debug branch and the matching MPU branch.

Changes:

- Replaced `lib/board/keepkey_usart.c` with the live stubs only: `dbg_print()` for non-emulator and `usart_init()` (`keepkey_usart.c:23`, `keepkey_usart.c:26`).
- Removed the USART3 unprivileged MPU branch from `lib/board/memory.c`; region 5 now always protects SYSCFG (`memory.c:118`).

Preserved public/live API: `dbg_print` and `usart_init` remain available.

## Checks run

- `git diff --check`
- `rg` dead-reference sweep for: `ETH_NATIVE`, `debug_intermediate_hash`, `ton_formatAmount`, `signed_metadata_signer_is_runtime`, `USART_DEBUG_ON`, `put_console_char`, `get_console_input`, `display_debug_string`, `read_console`, `USART3`
- `clang-format20 --dry-run --Werror` on all touched cleanup files
- `git diff --name-only` scope check for the requested firmware/header files

No build or test command was run by this agent.
