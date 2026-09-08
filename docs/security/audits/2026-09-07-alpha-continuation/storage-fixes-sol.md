# Storage findings C3-048 through C3-051 — implementation evidence

Repository: `/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware-alphafix`

Scope is stable for the combined build. I did not build, commit, push, or modify files outside the assigned storage/memory/test surface. Root's pre-existing session-clear, passphrase, and root-cache changes in `lib/firmware/storage.c` and the three appended Storage tests were preserved.

## C3-048 — corrupt storage must fail closed

Implemented a three-state boot decision rather than treating every `find_active_storage()` failure as a factory device:

- `lib/board/memory.c:334` adds `storage_has_record_evidence()`. After the active and recoverable-pending finders fail, it distinguishes erased/marker-only sectors from storage-shaped programmed data. It recognizes intact leading storage magic and also scans bytes after the 33-byte protection marker through the bounded record, which catches rejected CRC frames, corrupt pending frames, and legacy records whose leading magic was damaged.
- `include/keepkey/board/memory.h:285` declares the classifier with its sequencing contract.
- `lib/firmware/storage.c:1580-1603` tracks `storage_valid`. A verified pending record is recovered as before. If neither finder succeeds but record evidence remains, boot sets the location invalid, displays `Storage Corrupt. Reboot Device!`, shuts down, and returns before `storage_reset_impl()`, factory initialization, `storage_commit()`, or any erase.
- A truly erased or marker-only device still selects the default sector and initializes normally.

Regression coverage in `unittests/board/board.cpp`:

- Existing corrupt-pending case now asserts evidence remains (`:230-242`).
- Erased and exact marker-only sectors classify as empty (`:244`).
- CRC-rejected finalized records in each of S1/S2/S3 classify as evidence (`:252`).
- Damaged leading magic on a framed record remains detectable (`:267`).
- Damaged leading magic on a legacy record with payload remains detectable (`:278`).

No persistent or static RAM was added. The boot path adds one local `bool`; the classifier streams directly from mapped flash.

## C3-049 — bitcoin-only burned-version ladder

`lib/firmware/storage.c:1472-1500` now accepts only supported in-band underlying layouts:

- Values below V11 return `SUS_BitcoinOnlyLocked` rather than being interpreted as V11.
- V18 and V19 return `SUS_BitcoinOnlyLocked`. Those alpha formats are burned, and V19 used flag bit 20 for `pin_kdf_v2`; parsing it as V20 would clear the KDF selector before the automatic migration commit.
- Supported V11-V17 values still use their historical readers and migrate.
- V20 loads as current; future values remain locked.

`unittests/firmware/storage.cpp:871` covers underlying values 0, 10, 11, 16, 17, 18, 19, 20, and 21 under `BITCOIN_ONLY`. The expected statuses make the two burned versions and both range boundaries explicit.

## C3-050 — exact serializer bounds

`lib/firmware/storage.h:36-44` defines one set of exact serialized extents:

- V1: 481 bytes
- V2-V10: 559 bytes
- V11-V15: 1492 bytes
- V16: 2013 bytes (469-byte plaintext plus ciphertext at offset 1501)
- V17/V20: 2525 bytes

Readers and wrappers now enforce those contracts before changing the destination:

- `storage_readStorageV1()` (`lib/firmware/storage.c:939`) reads the serialized version only after the V1 minimum, then requires 559 bytes for every non-V1 record before the first destination write.
- V11 (`:1018`), V16 plaintext/composite (`:1081`, `:1136`, `:1200`), and V17 read/write (`:1213`, `:1240`) use the exact farthest extent.
- V1/V2/V11/V16/V17 wrappers (`:1340-1375`) guard `metadata + payload` and pass the real remaining length, eliminating the old `len - 44` underflow risk and false 852/1024-byte contracts.
- V20 aliases the V17 payload extent (`:1266`) and retains its full wrapper guard.

Canary regressions use fully allocated maximum-size buffers while shortening only the advertised length, so they are deterministic without ASan or actual invalid memory access:

- `LegacyV1ReaderRejectsTruncatedVersionTwoTransactionally` (`unittests/firmware/storage.cpp:234`) covers length 0, V1 one-short, the V1 boundary carrying a V2 version, V2 one-short, and exact V2.
- `LegacyV1AndV2WrappersAcceptOnlyCompleteFormats` (`:268`) checks one-short and exact wrapper boundaries.
- `LegacyWrapperReadersEnforceExactBoundsTransactionally` (`:303`) covers length 0, metadata underflow, one-short, and exact V11/V16/V17 boundaries. Short calls must leave the entire `ConfigFlash` canary unchanged.
- `CurrentCodecRejectsShortBuffersWithoutPartialWrites` (`:349`) provides the same length 0, metadata-underflow, one-short, and exact checks for both V20 writer and reader. Short writes must leave the full output buffer unchanged.

## C3-051 — dead storage surface

Removed genuinely dead production exports and implementations:

- V19 raw/wrapper codec.
- V11, V16, and V17 write wrappers, plus the V11 raw writer and V16 composite writer.
- PolicyV1 raw codec.
- Public `storage_getShadowMnemonic()`.
- Undefined camelCase `storageHasWipeCode()` / `storageChangeWipeCode()` declarations.
- The release-build no-op `storage_dumpNode()` symbol. Its declaration, implementation, and test now exist only under `DEBUG_LINK`; the debug message caller is already debug-only.

The surviving internal V16/V17 helpers are `static`. `rg` over `lib`, `include`, and `unittests` finds no references to the removed names.

Migration coverage does not depend on dead writers. `unittests/firmware/storage.cpp:34-50` contains test-only V17/V16 fixture builders. They start with the bounded V20 writer and clear fields absent from the historical layouts, including V20's generation bytes in legacy metadata padding. Existing AdvancedMode, large V16 migration-vector, and PIN-after-V17-reboot tests now use those fixtures. The V19 codec self-test and PolicyV1 codec self-tests were removed; the security-relevant legacy policy migration test remains.

## Files changed and stable

- `include/keepkey/board/memory.h`
- `include/keepkey/firmware/storage.h`
- `lib/board/memory.c`
- `lib/firmware/storage.c`
- `lib/firmware/storage.h`
- `unittests/board/board.cpp`
- `unittests/firmware/storage.cpp`

The pre-fix snapshot requested by root is under `/private/tmp/keepkey-storage-before/`, including storage source/internal+public headers, board memory source/header, and both test files. Snapshot SHA-256 values include:

- `storage.c`: `bde11a2e5170da4e1ff6410a4e04efaded2275cc076a44caf143e9064e90cd79`
- `storage.cpp`: `df40fb8ef6621fe350fcb008846aab395b0834e91f5b877ca911e58fe8929ca1`

## Validation status

- `git diff --check`: passed.
- Removed-symbol repository search: clean outside audit documentation.
- Root's combined build succeeded. Its first 609-test firmware run reached 608 passes; the sole failure identified legacy metadata padding copied by the test-only fixture. The fixture now clears V20 generation bytes 41-43 to reproduce the pinned historical V16/V17 encoding, and the affected pinned-golden test passes on rerun.
- Root's board suite passes 25/25, including all new corrupt-record evidence cases.
- The storage bounds and bitcoin-only tests can be compiled against the snapshot `storage.c` while retaining the current headers/memory helper to demonstrate the pre-fix failures. The board evidence tests require the new helper and directly exercise all classifier branches.
