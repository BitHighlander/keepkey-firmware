# KeepKey EOS/Solana C3 fix report — gpt55

Scope: owned files only. No commit, push, shared build, or subagents. Pre-fix evidence snapshot: `/private/tmp/keepkey-eos-solana-prefix-gpt55.txt`.

## Fixes applied

### C3-014 — Solana priority fee binding before attested display

Updated `lib/firmware/fsm_msg_solana.h` so priority-fee confirmation now runs immediately after signer verification and before certified schema, runtime schema, or native instruction display (`fsm_msg_solana.h:794`, `fsm_msg_solana.h:806`). The gate covers `SOL_TX_REVIEW_VERIFIED || certified || runtime_schema`; the old post-review verified-only gate was removed. Runtime schemas still require AdvancedMode before display/signing.

Existing parser/math coverage remains in `Solana.PriorityFeeOverflowSafe` and the x402/compute-budget parse fixtures; no certificate-generation test was added in this patch.

### C3-015 — dead Solana helpers/screens

Deleted unused production/test-only Solana helper APIs and constants:

- `SolanaKnownToken`, `SOL_KNOWN_TOKENS`
- `solana_parseTx()`
- `solana_findKnownToken()`
- `solana_deriveAssociatedTokenAddress()` / `SOL_PDA_MARKER`
- `solana_findTokenRecipientOwner()`
- `solana_findTokenInfo()`

Removed unreachable clear-sign screens for instruction types that the parser already forces opaque: `SYSTEM_CREATE_ACCOUNT`, `TOKEN_APPROVE`, `TOKEN_SET_AUTHORITY`, and the generic `UNKNOWN` instruction screen (`fsm_msg_solana.h:423`). Added `Solana.PartialInstructionScreensStayForcedOpaque` (`unittests/firmware/solana.cpp:1222`) to assert those parsed types remain opaque/blind-only rather than verified.

Left `solana_token_info_trusted()` intact because `unittests/firmware/signed_metadata.cpp` still directly tests that verifier outside this task ownership.

### C3-030 — EOS unknown action chunk common binding

Updated `lib/firmware/eos.c` so the first unknown-action chunk stores a SHA-256 digest of the canonical `EosActionCommon` fields and every continuation chunk must match it (`eos.c:54`, `eos.c:376`, `eos.c:396`, `eos.c:477`, `eos.c:486`). The digest covers account, action name, authorization count, and authorization actor/permission pairs in the same serialization used for the signed preimage.

SRAM note: added one 32-byte static digest and removed the existing 32-byte static final fingerprint buffer by making it stack-local, so static state is flat for this fix.

Added tests:

- `EOS.UnknownActionChunksRejectChangedCommonFields` (`unittests/firmware/eos.cpp:303`)
- `EOS.UnknownActionChunksAcceptSameCommonFields` (`unittests/firmware/eos.cpp:321`)

### C3-031 — EOS authorization key curve type constraints

Added a K1-only authorization-key check (`eosio.system.c:46`, `eosio.system.c:48`). Non-K1 key types now fail size/hash calculation, do not qualify for the standard derived-key display path, and are rejected before arbitrary-authorization display (`eosio.system.c:458`, `eosio.system.c:517`, `eosio.system.c:568`).

Added `EOS.AuthorizationRejectsNonK1KeysBeforeDisplay` (`unittests/firmware/eos.cpp:339`). The test checks R1 (`type=1`) rejection without consuming a confirm screen and K1 (`type=0`) acceptance with the expected two screens.

### C3-032 — EOS chain ID disclosure

Updated `fsm_msgEosSignTx()` to require `has_chain_id` and display the exact 32 signed chain-ID bytes via `confirm_bytes()` before session initialization (`fsm_msg_eos.h:97`). Existing chain behavior is preserved: no pinning/rejection by chain value, only disclosure.

Updated `EOS.SignTxRejectsNetUsageWordsOverflow` to preload the exact chain-ID page count on the valid half; the overflow half still rejects before the chain-ID screen.

### C3-033/C3-034 — EOS dead helper / memo bound cleanup

Deleted the unused `eos_compileString()` helper. Replaced the unreachable `256 < memo_len` guard with bounded `strnlen(action->memo, sizeof(action->memo))` and an explicit static assertion for the 256-byte protobuf field (`eosio.token.c:55`).

## Files changed

- `include/keepkey/firmware/solana.h`
- `lib/firmware/eos.c`
- `lib/firmware/fsm_msg_eos.h`
- `lib/firmware/eos-contracts/eosio.system.c`
- `lib/firmware/eos-contracts/eosio.token.c`
- `lib/firmware/solana.c`
- `lib/firmware/fsm_msg_solana.h`
- `unittests/firmware/eos.cpp`
- `unittests/firmware/solana.cpp`

`include/keepkey/firmware/eos.h` is owned but unchanged.

## Checks run

- `git diff --check`
- `rg` dead-reference sweep for removed Solana helpers and `eos_compileString`
- `/opt/homebrew/opt/llvm@20/bin/clang-format --dry-run --Werror` on all touched owned files

No shared build/full unit run was started by this agent.
