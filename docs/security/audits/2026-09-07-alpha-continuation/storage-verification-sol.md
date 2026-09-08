# Independent verification: C3-048 through C3-051

Verified read-only against `ed65a0ce9bbfd06d58a30a834f5245e86310a794` in
`/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware-alphafix`.
The storage-scope files matched `HEAD` during verification. No file in the repository
was modified and no build was run.

The verdict vocabulary below follows `docs/security/ALPHA-AUDIT-SOP.md`: a claimed
security exploit is confirmed only with a concrete reachable trace. The SOP also
requires unreachable surface to be deleted, so dead-code and false-contract findings
are classified explicitly even when they do not supply a present attacker primitive.

## C3-048 — CONFIRMED, P2 availability/storage-integrity defect; no wire-reachable trigger

**Claim:** a finalized record rejected for bad CRC is subsequently either parsed by
the magic-only default-sector fallback or erased while initializing a new empty
record.

**Verdict:** Confirmed on current `HEAD`. The destructive/adoption traces are fully
determined by the sector state machine. This is a concrete loss-of-wallet-state and
fail-open integrity defect. I did not find a USB/protobuf input that creates the bad
CRC: the initiating condition is flash corruption, a marginal cell, or a physical
fault. It therefore should not be described as a remote exploit. A physical attacker
who can fault the CRC decision can trigger the same path, but the demonstrated impact
is availability/integrity, not extraction of the seed.

**Evidence and concrete trace:**

1. `lib/board/memory.c:278-331` scans all three sectors. A record with `stor` magic is
   accepted only if its trailer is erased (legacy) or its `crc1` trailer and CRC verify.
   The explicit rejection is at `lib/board/memory.c:312`.
2. `lib/firmware/storage.c:1708-1724` tries a verified active record and then a
   verified pending record. If neither exists, it assigns `STORAGE_SECT_DEFAULT`
   (`FLASH_STORAGE1`) without retaining the fact that validation failed.
3. `lib/firmware/storage.c:1726-1737` then uses
   `storage_isActiveSector()`. That helper, `lib/firmware/storage.c:179-182`, checks
   only the four-byte `stor` magic and does not repeat the trailer or CRC check.
4. If the corrupt finalized record is in S1 and its leading magic is intact, the
   sequence is `find_active_storage=false` -> `find_pending_storage=false` -> choose
   S1 -> magic-only check succeeds -> `storage_fromFlash()` at
   `lib/firmware/storage.c:1747`. The corrupt bytes are deserialized. For a V17 record,
   `storage_fromFlash()` returns `SUS_Updated` at `lib/firmware/storage.c:1577-1580`,
   and `storage_init()` calls `storage_commit()` at lines 1754-1757. The resulting V20
   record has a new valid CRC, permanently laundering the corruption.
5. If the only corrupt finalized record is in S2, S1 is the erased spare and S3 is
   the old marker. The default S1 magic check fails, so lines 1735-1736 initialize and
   commit an empty configuration. `storage_commit()` selects S3 as the replacement
   (`next(next(S1))`) at lines 2023-2029, erases/writes it at 2043-2049, retires S1 at
   2066, installs S3's marker in S1 through `recover_pending_storage()`
   (`lib/board/memory.c:404-430`), and erases S2 at `storage.c:2070`. The corrupt S2
   wallet is gone.
6. If the only corrupt record is in S3, S1 holds its marker and S2 is spare. The
   default S1 magic check again fails. The new empty commit chooses S3 at lines
   2028-2029 and erases the corrupt wallet immediately at line 2044. The rest of the
   handoff then replaces the marker and spare.
7. A corruption of S1's `stor` word follows the destructive initialization trace
   rather than the unverified parse. Thus “S1 is loaded unverified” is correct only
   when the magic survives; the overall finding remains confirmed.
8. Existing tests stop one layer too early. `unittests/board/board.cpp:184-191`
   proves a corrupt new record falls back to a still-valid legacy record, and
   lines 231-239 prove a corrupt pending record is not finalized. There is no test
   for the no-valid-record handoff into `storage_init()`.

**Root cause:** validation produces only a boolean “found usable record.” The caller
conflates “all sectors are erased” with “storage-shaped data exists but failed
integrity,” then uses a second, weaker magic-only predicate to decide whether the
default sector is parseable. The transaction logic assumes `storage_location` always
names a validated old active record, an assumption violated by the factory-default
fallback.

**Smallest viable remediation:** preserve the validation result through
`storage_init()`. After both active and pending discovery fail, scan S1-S3 for evidence
of a record: intact `stor` magic or any non-erased record trailer at
`STORAGE_RECORD_DATA_LEN`. If such evidence exists, show a static corruption warning
and halt without calling `storage_fromFlash()`, `storage_resetUuid()`, or
`storage_commit()`. Factory initialization should occur only when no record evidence
exists. Once an active or recovered-pending record is selected, use the prior verified
result instead of `storage_isActiveSector()`; delete the weaker helper if it has no
remaining caller. A small enum returned by discovery (`NONE`, `VALID`, `CORRUPT`) is
cleaner than two loosely coupled booleans but not required for the fix.

Checking the non-erased trailer matters in addition to `stor`: it catches corruption
of the leading magic and also the historical V18/V19 images whose bytes at the new
trailer offset are non-erased. Only perform this corruption check when no valid active
or pending record exists, so the already-tested fallback from a corrupt candidate to
a preserved valid record continues to work.

**Regression strategy:** extend the emulator-backed storage-selection fixture. Build
a valid framed record, flip one covered payload/CRC bit, place it as the only record
in S1, S2, and S3 in separate cases, and assert that `storage_init()` performs no flash
erase/write and reaches the corruption disposition. Add leading-magic corruption and
corrupt-pending cases. Retain controls for (a) all-erased flash initializes once,
(b) a valid legacy record remains readable, and (c) a corrupt candidate plus a valid
older record selects the valid record. If shutdown is hard to observe in the firmware
suite, test a board-level `storage_record_presence()` classifier exhaustively and add
one firmware test that proves `storage_init()` consumes `CORRUPT` without committing.

## C3-049 — CONFIRMED, P3 upgrade/lockout defect

**Claim:** the bitcoin-only version ladder sends burned underlying versions 18/19,
and underlying 0-10, to incompatible readers instead of refusing them.

**Verdict:** Confirmed on current `HEAD`, with a stronger and more precise impact for
historical `10019` wallets. This is not merely a record forged by a physical attacker:
commit `e109404ee359375063a7024c240365d636984552` introduced the bitcoin-only band and
V19 together, stamped newly created bitcoin-only seeds as `10019`, wrote them with the
V19 KDF flag, and is explicitly part of the burned-alpha history. A current bitcoin-only
firmware boot can irreversibly discard the metadata needed to unwrap such a PIN-protected
wallet. There is no current USB input that selects `storage_fromFlash()`; the trigger is
booting the current image over the historical on-device record.

**Evidence and concrete trace:**

1. `version_from_int()` maps every raw version at or above 10000 to the single
   `StorageVersion_BTC_ONLY` enum at `lib/firmware/storage.c:267-287`.
2. In a `BITCOIN_ONLY=1` build, the dispatch at `lib/firmware/storage.c:1597-1625`
   subtracts 10000. It rejects only values greater than 20. Values `<=15` go to
   `storage_readV11()`, 16 to V16, 17 to V17, and every other accepted value—18, 19,
   and 20—to `storage_readV20()` at lines 1614-1621.
3. The ordinary multi-chain switch explicitly refuses burned 18 and 19 at
   `lib/firmware/storage.c:1581-1590`. `lib/firmware/storage_versions.inc:26-34`
   documents why their layouts cannot be reused. The bitcoin-only branch fails to
   mirror that disposition.
4. Historical `e109404ee` proves legitimate provenance. Its `storage.h` sets
   `STORAGE_VERSION=19` and `STORAGE_VERSION_BTC_ONLY=10019`; its seed/import paths
   call `storage_stampBitcoinOnlySeed()`. Its V19 serializer stores `pin_kdf_v2` in
   flags bit 20 and its commit writes `storage_writeV19()`.
5. On current `HEAD`, `storage_readV20()` calls `storage_readStorageV17()`
   (`lib/firmware/storage.c:1408-1413`). The V16 plaintext reader unconditionally sets
   `pin_kdf_v2=false` at `lib/firmware/storage.c:1263-1266`; V20 never restores bit 20.
   The wrapped storage key and its fingerprint are copied unchanged from offsets 80
   and 144 (`storage.c:1280-1281`).
6. For a PIN-protected historical 10019 record in S1, C3-048's CRC fallback first
   makes it reachable despite the non-erased bytes at the new trailer offset. The
   bitcoin-only ladder reads it as V20, clears `pin_kdf_v2`, restamps version 10020,
   and returns `SUS_Updated` because 19 != 20 at lines 1623-1625.
   `storage_init()` immediately commits at lines 1754-1757, before any PIN attempt.
   Because the PIN is not cached, `storage_commit()` preserves the old wrapped key
   (`storage.c:1994-1998`) but serializes flags without bit 20. The original V19 PBKDF
   parameters are no longer described by flash, so current firmware derives V16 via
   `storage_activePinKdfVersion()` (`storage.c:471-480`) and the correct PIN cannot
   match the fingerprint.
7. The recovered finding's “attempts climb to a wipe threshold” wording is inaccurate.
   `pin_protect()` increments and commits failed attempts (`lib/firmware/pin_sm.c:256-270`)
   and imposes exponential delay; it does not contain a retry-count wipe threshold.
   This does not reduce the core impact: the harmful rewrite already happened during
   boot, and ordinary firmware no longer has the persisted KDF selector needed to
   recover the wallet.
8. If the historical 10019 image rests in S2 or S3, C3-048 erases it during factory
   initialization before this dispatch is reached. Both sector outcomes are destructive.
9. Underlying 0-10 are indeed misrouted to V11. I found no firmware history that
   legitimately stamped bitcoin-only versions 10000-10010—the band entered at V17—so
   this subcase lacks a genuine upgrade provenance and requires forged/corrupt flash.
   It is still a false dispatch contract and should be rejected.
10. The current bitcoin-only regression test enshrines the bug:
    `unittests/firmware/storage.cpp:729-760` defines “older” as `STORAGE_VERSION-1`,
    currently 19, and asserts it is not locked.

**Root cause:** the reserved band collapses all underlying numbers into one enum, then
reimplements the normal version switch as an incomplete range ladder. The code assumes
every lower numeric version is a supported predecessor, ignoring burned holes and the
different V1/V2 layouts.

**Smallest viable remediation:** before calling any reader in the bitcoin-only branch,
return `SUS_BitcoinOnlyLocked` for underlying 18 or 19 and for underlying values below
11. `SUS_BitcoinOnlyLocked` is safer than `SUS_Invalid`: `storage_init()` does not commit
on the locked path (`storage.c:1759-1765`), so an old firmware or explicit recovery tool
can still recover a legitimate 10019 wallet. Then dispatch 11-15 to V11, 16 to V16,
17 to V17, and 20 to V20; continue locking values above the current version. An explicit
`switch (underlying)` or a shared version-to-reader classifier avoids creating another
range hole when a version is burned.

**Regression strategy:** in the `BITCOIN_ONLY=1` firmware-unit configuration, replace
the generic `STORAGE_VERSION-1` case with explicit cases: 10017 returns `SUS_Updated`,
10018 and 10019 return `SUS_BitcoinOnlyLocked`, 10020 returns `SUS_Valid`, and 10021
returns `SUS_BitcoinOnlyLocked`. Add 10000 and 10010 refusal controls. For 10019, use a
checked-in minimal historical fixture or a test-only historical encoder that sets a
recognizable wrapped key and bit 20; assert `storage_fromFlash()` never mutates it and
an integration-level boot performs no commit/erase. Do not retain the production V19
codec merely to make this test fixture.

## C3-050 — REFUTED as a current security exploit; CONFIRMED latent P3 bounds-contract defect

**Claim:** V1/V11/V16/V17 serializer length guards do not cover their real accesses.

**Verdict:** No current attacker-reachable out-of-bounds access exists, so the concrete
security claim is refuted under the SOP reachability rule. The guard/API defect itself
is confirmed and should be fixed as latent memory-safety hygiene. These functions are
not all dead: the legacy readers are live migration code. Their `len` parameters and
guards falsely promise safe operation on much smaller buffers.

**Evidence and concrete trace:**

1. `storage_writeStorageV11()` checks 852 at `lib/firmware/storage.c:1038-1039` but
   copies 1024 bytes at offset 468 at line 1097. It requires 1492 bytes.
   `storage_readStorageV11()` has the same 852 check at lines 1100-1101 and the same
   farthest access at line 1160.
2. `storage_writeStorageV16()` has no composite-size check at lines 1218-1234. It
   calls the 852-byte-guarded plaintext writer and then copies the full 1024-byte
   `encrypted_sec` at offset 1501, requiring 2525 bytes. `storage_readStorageV16()`
   likewise has no composite check at lines 1299-1309 and reads the historical
   512-byte ciphertext at offset 1501, requiring 2013 bytes.
3. `storage_writeStorageV17()` and `storage_readStorageV17()` have no composite check
   at `lib/firmware/storage.c:1311-1352`; each accesses 1024 bytes at offset 1501 and
   therefore requires 2525 bytes. Their delegated plaintext helper checks only 852.
4. The wrappers at `lib/firmware/storage.c:1461-1494` accept any `len >=1024`, then
   discard the real extent and pass literal 852 to the inner serializer. Thus a caller
   supplying the documented minimum can overrun even though both layers' checks pass.
5. The V1 detail needs qualification. `storage_readStorageV1()` checks 481 at
   `storage.c:961-963`; only a record whose inner version is not 1 reads the cache at
   offset 484 for 75 bytes (lines 1002-1007), requiring 559. The production V1 wrapper
   is selected only for raw version 1, so that conditional access is skipped. The V2
   wrapper's outer `528 + 75 = 603` check (`storage.c:1454-1458`) does cover the
   required absolute 603 bytes, despite passing a false inner length of 481. Direct
   callers can still violate the helper's advertised contract.
6. All production read paths are safe today: every call from `storage_fromFlash()` at
   `storage.c:1534-1621` passes a pointer to a complete 16 KiB flash sector. The only
   legacy writer-wrapper callers are unit tests, using 2570-byte or 16 KiB vectors
   (`unittests/firmware/storage.cpp:419-421`, `804-806`, and `1442-1444`). Direct V1
   test callers use 559 or 852 bytes. No host-controlled length reaches these APIs.
7. V20 is correctly shaped: `V20_STORAGE_LEN` is 2525 at `storage.c:1360`, and both
   raw and wrapper functions enforce/forward that extent at lines 1399-1413 and
   1497-1511.

**Root cause:** the code treats `len` as documentary rather than authoritative. The
composite functions rely on a small delegated plaintext guard and perform larger
unconditional trailing accesses. Wrappers pass historical placeholder literals rather
than the caller's remaining extent. `void` return types also make an early refusal
indistinguishable from a successful parse/write.

**Smallest viable remediation:** define named serialized lengths and check each
composite before any mutation: V11 read/write 1492, V16 read 2013, V16 write 2525,
and V17 read/write 2525. Make wrappers require metadata plus the corresponding length
and pass `len - STORAGE_METADATA_LEN` to inner functions. For the shared V1 helper,
either require 559 unconditionally or choose 481/559 after safely reading the inner
version; pass the real remainder from V1/V2 wrappers. If changing the API is acceptable,
return `bool` so callers can fail closed rather than silently receiving a partially
zero destination.

**Regression strategy:** add ASan/UBSan firmware-unit cases (CI already runs the suite
with `-fsanitize=address,undefined`) for every raw and wrapper function. For each reader
and writer, call once at required-length minus one and assert no destination/buffer byte
changes, then call at exactly the required length and assert the final serialized byte
is read/written. Put redzones/canaries around the buffers so a future farthest-offset
change fails independently of the guard assertion. Include V1 records with inner
versions 1 and 2 to exercise both conditional extents. Production callers remain a
full-sector control.

## C3-051 — CONFIRMED P3 under the SOP dead-surface rule; no present exploit

**Claim:** obsolete storage codecs, test-only writers, unused secret accessors,
undefined declarations, and a release stub remain compiled/exposed.

**Verdict:** Confirmed as a dead-surface/hygiene finding, which the SOP explicitly says
must be removed even without a host trigger. There is no current runtime exploit and no
wire path to these functions. One subclaim needs narrowing: `storage_dumpNode()` is
genuinely reachable in a `DEBUG_LINK=1` firmware, but its `DEBUG_LINK=0` global no-op
definition is dead.

**Evidence and call classification:**

* `storage_writeStorageV19()` / `storage_readStorageV19()` at
  `lib/firmware/storage.c:1416-1427` and their wrappers at lines 1514-1523 are called
  only by `unittests/firmware/storage.cpp:1389-1407`. No `storage_fromFlash()` case
  calls them. Worse, these are not faithful historical V19 codecs: they layer bit 20
  over the V20 passkey codec, despite V19 being documented as a burned clear-sign/KDF
  layout in `storage_versions.inc:26-34`. Their presence invites exactly the wrong
  reader hookup described by C3-049.
* `storage_readPolicyV1()` / `storage_writePolicyV1()` at
  `lib/firmware/storage.c:322-345` are called only by the two codec unit tests at
  `unittests/firmware/storage.cpp:55-82`. The legacy V1/V2 reader now discards
  flash-controlled policy state and calls `storage_resetPolicies()` at
  `storage.c:982-993`; the old codec has no production purpose.
* `storage_writeV11()`, `storage_writeV16()`, and `storage_writeV17()` at
  `lib/firmware/storage.c:1467-1494` have no production callers. V16 and V17 are used
  only to synthesize legacy records in unit tests; V11 has no caller outside its
  definition. `storage_writeStorageV11()` becomes dead if its wrapper is removed, and
  `storage_writeStorageV16()` is likewise wrapper-only. The raw V17 writer remains
  live because `storage_writeStorageV20()` calls it at line 1401.
* `storage_getShadowMnemonic()` at `lib/firmware/storage.c:2682-2685` returns a pointer
  to the plaintext mnemonic and has no caller anywhere. Its public declaration is
  `include/keepkey/firmware/storage.h:175-176`.
* `storageHasWipeCode()` and `storageChangeWipeCode()` at
  `lib/firmware/storage.h:271-273` have neither definitions nor callers. They duplicate
  the naming/domain of the live snake_case APIs without implementing them.
* `storage_dumpNode()` is called from `lib/firmware/fsm_msg_debug.h:23-31` only inside
  `#if DEBUG_LINK`. Its public declaration is correctly under `#ifdef DEBUG_LINK` at
  `include/keepkey/firmware/storage.h:225-239`. The definition at
  `lib/firmware/storage.c:2097-2123`, however, exists globally in every release and
  compiles to an empty `(void)dst; (void)src;` stub when debug link is off. The unit
  test at `unittests/firmware/storage.cpp:289-315` explicitly tests this no-op release
  behavior instead of omitting the symbol.

**Root cause:** successive storage migrations retained implementation APIs to support
unit fixture generation and historical experiments. Because the functions are global
and share a production translation unit, ordinary unused-function diagnostics do not
identify them. Conditional compilation was applied inside `storage_dumpNode()` rather
than around the symbol.

**Smallest viable remediation:** delete the V19 codec and round-trip test, the PolicyV1
codec and its two codec-only tests, `storage_writeV11()` and its raw writer if no caller
remains, `storage_writeV16()` and its raw writer after replacing test fixture generation,
`storage_getShadowMnemonic()` and its public declaration, and the two undefined
camelCase prototypes. Keep `storage_writeStorageV17()` because V20 uses it; remove only
the dead V17 wrapper after adapting tests. Wrap the entire `storage_dumpNode()`
definition in `#if DEBUG_LINK` and compile/test `DumpNode` only in that configuration.
Prefer checked-in legacy byte fixtures or test-only helpers in the unit target over
shipping legacy writers in the firmware object.

**Regression strategy:** preserve behavior-level tests rather than codec-presence tests:
V1/V2 flash cannot restore a policy name such as `AdvancedMode`; burned normal and
bitcoin-only versions 18/19 are refused without a commit; V17 migrates to V20; and the
debug-link build still emits the expected node. Add a release linker-map or `nm` gate
that rejects `storage_readV19`, `storage_writeV19`, `storage_getShadowMnemonic`, and
`storage_dumpNode` in a `DEBUG_LINK=0` artifact. Making all remaining translation-unit
helpers `static` where possible lets `-Wunused-function` prevent future dead helpers
from accumulating.

## Dependency/order note

C3-048 and C3-049 overlap. Fix C3-048 first so a historical 10019 image in any sector
cannot be parsed or erased through the default fallback. Still fix C3-049 independently:
`storage_fromFlash()` is a public internal API, and a future record classifier or test
could otherwise route a banded burned version directly into the incompatible V20 reader.
C3-051's V19 codec deletion removes the most tempting way to regress that dispatch.
