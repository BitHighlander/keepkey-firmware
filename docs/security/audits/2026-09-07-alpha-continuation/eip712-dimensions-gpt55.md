# EIP-712 nested fixed-array dimension fix

Task: fix the nested fixed-array dimension issue found in the `ed65a0ce9` diff review, including the corrected Solidity/EIP traversal order. Scope limited to `lib/firmware/eip712_stream.c`, `include/keepkey/firmware/eip712_stream.h`, and `unittests/firmware/eip712_stream.cpp`.

Files changed:

- `lib/firmware/eip712_stream.c`
- `unittests/firmware/eip712_stream.cpp`

Header status: `include/keepkey/firmware/eip712_stream.h` was not changed.

Implementation:

- Added `elem_dims[4]` to the array side of `Eip712Frame`'s existing union.
- Copied the bounded `m->type.array_levels[]` values into the array frame after the existing `array_levels_count > 4` guard.
- Propagated `elem_dims` into nested array frames.
- Set `pending_declared_dim` from `array_levels[levels_total - 1 - level_index]`, so the value walker consumes dimensions from the rightmost bracket inward while keeping the existing left-to-right spelling contract.

SRAM note:

The added `uint32_t elem_dims[4]` lives only in the array descriptor branch of the existing frame union. On the expected 32-bit layout, the union remains dominated by the struct descriptor branch (`name[32] + type_hash[32] + have_type_hash`, rounded to 4-byte alignment), so this should not increase static `e712.stack` storage. Root's serialized device build should still verify the final linker reserve.

Tests added/updated:

- `RejectsOuterFixedArrayLengthMismatch`: `uint256[2][3]` rejects outer length `2`, proving the rightmost `3` is consumed first.
- `RejectsInnerFixedArrayLengthMismatch`: `uint256[2][3]` accepts outer length `3`, then rejects inner length `3`, proving the left `2` is enforced after descent.
- `MultidimensionalFixedArrayUsesSolidityOrder`: valid `uint256[2][3]` completes and checks the final `message_hash` using three fixed-length inner arrays of two values each.
- `OuterDynamicArrayWithFixedInnerElementsCompletes`: `uint256[2][]` starts with a dynamic outer length and enforces fixed-length-2 inner arrays.
- `InnerDynamicArrayWithFixedOuterLengthCompletes`: `uint256[][2]` enforces fixed outer length `2` and permits dynamic inner lengths, including an empty inner array.

Verification performed:

- `/opt/homebrew/opt/llvm@20/bin/clang-format --style=file --dry-run --Werror lib/firmware/eip712_stream.c unittests/firmware/eip712_stream.cpp`
- `git diff --check -- lib/firmware/eip712_stream.c unittests/firmware/eip712_stream.cpp include/keepkey/firmware/eip712_stream.h`
- No rebuild or new test binary run per root serialization. An earlier stale prebuilt `build-emu/bin/firmware-unit --gtest_filter='Eip712Stream.*'` passed 30 old tests, but it did not include these source tests and is not counted as validation.

Spec/source note:

The primary EIP-712 specification defines arrays as fixed or dynamic via `Type[n]` / `Type[]`, and defines array values as `keccak256` over the concatenated encodings of their contents. Solidity's type docs define `T[k]` as an array containing `k` elements of type `T`, even when `T` is itself an array; for example `uint[][5]` is an array of five dynamic arrays, and the notation is reversed compared with some languages. The firmware wire contract in `messages-ethereum.proto` maps bracket groups into `array_levels` in written left-to-right order for type spelling, so the live value traversal must consume those dimensions rightmost-first.
