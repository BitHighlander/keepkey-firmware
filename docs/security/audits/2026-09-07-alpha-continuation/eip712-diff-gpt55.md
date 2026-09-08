# EIP-712 diff review: ed65a0ce9

Scope: adversarial read-only review of commit `ed65a0ce9bbfd06d58a30a834f5245e86310a794` in `/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware-alphafix`, following `docs/security/ALPHA-AUDIT-SOP.md`.

Files read: `docs/security/ALPHA-AUDIT-SOP.md`; `git show --stat/--name-only/--unified=80 ed65a0ce9`; full changed regions and callees in `include/keepkey/firmware/eip712_stream.h`, `lib/firmware/eip712_stream.c`, `lib/firmware/fsm_msg_ethereum.h`, `lib/firmware/fsm_msg_common.h`, `lib/firmware/storage.c`, `lib/firmware/ethereum.c`, `unittests/firmware/eip712_stream.cpp`; supporting checks in `lib/firmware/fsm.c`, `lib/firmware/pin_sm.c`, `include/keepkey/transport/messages-ethereum.options`, generated `build-emu/lib/transport/messages-ethereum.proto`, `include/keepkey/board/layout.h`, and the prior audit record `docs/security/audits/2026-09-07-alpha-71ba84436-cycle3.md`.

Verdict: one actionable finding remains. It is pre-existing in the parent of `ed65a0ce9`; this commit did not introduce it, but the same EIP-712 stream surface still accepts malformed nested fixed arrays after the new fixes.

## P2: nested fixed array dimensions after the first are not enforced

Classification: pre-existing gap still present at `ed65a0ce9`, not introduced by the commit.

Location:

- `lib/firmware/eip712_stream.c:949-973` records the first array dimension in `e712.pending_declared_dim = m->type.array_levels[0]` when a member array is entered.
- `lib/firmware/eip712_stream.c:1012-1027` compares the incoming length against `pending_declared_dim`, so the first fixed dimension is enforced.
- `lib/firmware/eip712_stream.c:717-734` stages nested array frames, but sets `e712.pending_declared_dim = 0` for every inner level instead of using the next declared dimension from the type.
- `lib/firmware/eip712_stream.c:131` and `build-emu/lib/transport/messages-ethereum.proto:321-329` define `array_levels` as the written Solidity dimensions, with `0` meaning dynamic and non-zero values meaning fixed.

Concrete trace:

1. Host starts `EthereumSignTypedData` with a message struct containing `uint256[2][2] amounts` (`array_levels_count = 2`, `array_levels = {2, 2}`).
2. The device hashes the type spelling as `uint256[2][2]` via `eip712_type_name()`, so the schema commitment says both dimensions are fixed at 2.
3. The walker requests the outer length. Because `pending_declared_dim` was set from `array_levels[0]`, `eip712_stream_on_value()` correctly rejects any outer length other than 2.
4. For each inner array, `drive_array_element()` creates the nested frame and sets `pending_declared_dim = 0`.
5. The next `EthereumTypedDataValueAck` length is therefore treated as dynamic. Lengths such as 1, 3, or 0 are accepted as long as `slot_base + len <= EIP712_MAX_SLOTS`.
6. The device displays and hashes exactly the supplied elements, then signs `hashStruct(message)` under a type hash that declares `uint256[2][2]`.

Impact:

This is not a display truncation bug: the user sees the values that are hashed. The issue is schema/value mismatch. The signature is produced for a value shape that violates the fixed-size type already committed into `typeHash`. A compliant EIP-712 encoder should not accept a value whose inner fixed dimensions disagree with the declared type. This can produce device signatures over malformed typed data that other encoders/verifiers will not reproduce, and it weakens the commit's "fixed dimension is part of the type string and therefore of typeHash" invariant to only the outermost dimension.

Why this is pre-existing:

The same `drive_array_element()` assignment appears in the parent at `ed65a0ce9^:lib/firmware/eip712_stream.c:721` (`e712.pending_declared_dim = 0`). The first-dimension check also exists in the parent at `ed65a0ce9^:lib/firmware/eip712_stream.c:985-988`. `ed65a0ce9` did not add the bug, but it leaves the gap open.

Suggested fix:

Carry the declared dimensions in the array frame, or store the next declared dimension before requesting each nested length. In the current shape, `drive_array_element()` should set `pending_declared_dim` from the staged inner level, e.g. conceptually `array_levels[arr->level_index + 1]`, but the frame currently does not retain the `array_levels[]` values beyond `levels_total` and `level_index`. A compact fix is to add a small fixed array of up to 4 `uint32_t` dimensions to the array descriptor, copy `m->type.array_levels[]` when the array frame is staged, propagate it into nested array frames, and use `dims[inner->level_index]` for `pending_declared_dim`.

Add a unit test that fails today:

- Define `amounts` as `uint256[2][2]`.
- Feed outer length `2`.
- Feed first inner length `1`.
- Expect `eip712_stream_on_value()` to return false with `"EIP-712 array length does not match its declared size"`.

## Sound areas reviewed

- Schema binding added by `ed65a0ce9` is materially sound for segment replacement. `eip712_stream_on_struct()` validates member names/types, then hashes and stores the canonical segment for `next_step.struct_name` before PH_DISCOVER/PH_STREAM/PH_MEMBER dispatch. Re-fetching a previously named type with renamed members, removed members, changed child type, or replacing a struct array with `bytes32` fails before the new ack is used.
- The `Eip712Next` union is used consistently with `kind`: struct requests read only `struct_name`, value requests read only `member_path`, failures read only `error`, and done reads only hashes/path. `eip712_stream_abort()` now clears both `e712` and `next_step`; completion intentionally clears only `e712` after populating the DONE payload so the FSM can consume it.
- The frame union is consistent with `is_array`: struct frames use `name/type_hash/have_type_hash`, array frames use `elem_*`, `levels_total`, `level_index`, and `array_len`. I did not find a stale-field path introduced by the union conversion.
- Leaf display-vs-signed checks are improved. Dynamic strings and bytes are refused before display when the complete formatted body would exceed `BODY_CHAR_MAX` (`352`), and tests cover the 351-character string and 171-byte dynamic bytes boundaries. Validation still runs before display and hashing.
- Session teardown fixes from the prior audit are wired: `fsm_msgCancel()` and `session_clear()` now call `eip712_stream_abort()`, and both `EthereumTypedDataStructAck` and `EthereumTypedDataValueAck` handlers now run `CHECK_PIN`.
- Nanopb bounds support the stream assumptions: `EthereumTypedDataValueAck.value` max size is `1024`, `EthereumTypedDataStructAck.members` max count is `32` and the stream rejects above `EIP712_MAX_SLOTS` (`12`), and `array_levels` max count is `4`.

## Notes

I did not run builds or tests per the task instruction. I also did not request subagents or make repository edits. The untracked `build-emu/` and `emulator.img` in the target checkout were left untouched.
