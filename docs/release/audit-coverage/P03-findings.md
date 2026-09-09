# P03 setup and storage findings

## P03-001: aborted reset resumed to commit and Success

Affected all three full emulator predecessors: 176cc998d (7.14.2),
c23460ba9 (7.14.3, duplicate-only cleanup above the tested implementation),
and 5b2a62ce0 (7.15). Send ResetDevice and EntropyAck, then GetCoinTable while
the backup warning is waiting for confirmation. Tiny-message rejection calls
sendFailureWrapper, which aborts setup and emits Failure. Acknowledge remaining
screens: all three returned Success "Device reset" despite the aborted ceremony.
The first probe stopped at the next ButtonRequest and therefore was insufficient;
the complete bounded continuation establishes the defect.

The shared setup_commit previously trusted its caller and wrote staged settings
without rechecking authorization. It now requires the expected live SetupKind
before any storage setter, returns bool, and reset/recovery callers only report
success if it committed. This protects the commit boundary; it does not claim
that every suspended state machine immediately unwinds after transport rejection.
Those wider interactions remain an open P02/P03 review obligation.

Staged fork units:
- 7.14.2 PR #704, 7b26c58dc, above frozen 176cc998d.
- 7.14.3 PR #705, e298e08a7, above frozen c23460ba9.
- 7.15 PR #706, 8ac4bd9df, above frozen 5b2a62ce0.

The same host sequence now ends in Failure on all three. Native regression
CommitRefusesAbortedOrDifferentCeremony covers disarmed and wrong-kind cases.
Full native suites: 157 / 192 / 503 passing respectively. Normal 12-, 18-, and
24-word reset flows with capture pass on each full emulator. An initial 7.14.3
normal-run attempt overlapped the still-running 7.15 native suite and failed to
start its emulator; discarded that attempt and reran all normal flows serially.
No claim of Bitcoin-only or combined-CI validation for these new heads yet.
Repeatable owned-emulator probe: rehearsals/setup_rejection.py CHECKOUT BUILD_DIRECTORY.

## Related completed wire checks

At the preceding 7.14.3 implementation, Bitcoin-only GetCoinTable rejected
malformed ranges and enumerated exactly two entries. Existing product tests
verified names Bitcoin/Testnet and the correct firmware variant. Full variant
previously enumerated 589 entries; this closes the variant-specific wire check,
not the remaining storage/setup audit.

### P03-001 follow-up validation

At the staged commit-authorization fixes, normal recovery succeeds both without
PIN/passphrase and with PIN/passphrase on all three full emulators. Existing
host tests verify recovered mnemonic and resulting protection behavior.

Bitcoin-only variants rebuilt successfully at e298e08a7 (7.14.3) and 8ac4bd9df
(7.15). All 92 / 94 native tests pass respectively. The aborted-reset wire
rehearsal terminates with Failure on both, and both normal recovery tests pass
on each Bitcoin-only emulator. No skips counted as passes.

Inspected the possible pre-arm resurrection path: setup_abort clears staged;
setup_stagePin refuses an unstaged setup, and setup_arm assigns SETUP_NONE
when staged is false. Thus a cleared stage does not re-arm through that path.
No additional defect established there. Later EntropyAck is gated by setup_require.

Current integration runs for the new older-release heads are 34295659497
(7b26c58dc) and 34295661595 (e298e08a7). Earlier backup-fix runs 34294763501
and 34294765461 completed successfully, but do not validate subsequent Ping
and setup changes. Their artifact evidence has not been fully inspected for
canonical advancement. The superseded P00 run 34294793245 is terminal cancelled.

### Reset implementation review and expanded host suite

Traced 7.14.3 reset staging and rollback, arming after prompts, entry and commit
kind checks, initial entropy cleanup, bounded mnemonic formatting (page bound
checked before indexing), final temporary-buffer cleanup, and debug-only digest
accessors. Dice/RNG implementations remain P09 dependencies; this does not close
their audit. All eight reset host tests pass on full and Bitcoin-only 7.14.3,
covering dice, failed PIN, re-entry, initialized-device refusal and 12/18/24 words.

7.15 previous integration 34293571582 completed successfully at cecf1ea20239d140cb43dc0629219fd9179ae452. New accumulated head 8ac4bd9df is dispatched as
34295830100 with publication disabled. No canonical advancement yet.

## P03-002: dice reset test duplicates a debug backup word group (fix staged)

Expanded full 7.15 reset suite: seven tests pass, test_reset_device_dice fails
its final mnemonic equality. Observed one four-word group repeated twice while
the expected mnemonic contains it once. The dice loop appends read_reset_word
on every ButtonRequest. confirm_constant_power_paged emits one request per
physical debug subpage; reset.c retains the same logical group for those
subpages. The normal reset helper already recognizes that repeated-group
protocol, whereas the dice helper does not. This is a test-collection mismatch
that requires correction and revalidation; do not suppress the equality check.
7.14.3 has the same dice collector and debug paging semantics; applicability
to its random inputs remains to be exercised. 7.14.2 has no dice product feature.
The full 7.15 suite is not counted as passing.

### P03-002 correction and verification

Host PR #84 (7.14.3, ec828d40f7e1f296d52566abcee59c979e562209) and #85
(7.15, 081fad067f3b9bdf0bb2cc17ea95601e65a0897e) collect consecutive reports
of the same logical group once, matching the existing normal-reset helper.
The final exact mnemonic equality assertion remains; an explicit expected
word-count assertion was added. This does not change firmware signing/setup.

Twenty corrected dice resets pass per release. Twenty old-collector 7.14.3
resets also passed; do not claim reproduction on that sample. Its change is
applicable through the shared debug-subpage protocol. One initial 7.14.3
baseline launch overlapped an active 7.15 run and its emulator refused to start;
discarded that attempt, then ran the complete baseline and correction serially.

Firmware pins: PR #707, 27865aa32 (7.14.3), and PR #708, 2b891ceb8 (7.15),
each above its frozen commit-authorization fix. Exact dependency fetch succeeds
through the configured repository URL. All eight reset tests pass using each
pinned dependency. Combined CI for these newer pins remains pending. 7.14.2
has no dice feature and receives no test change for it.

## Bounded cipher observer review across all products

Both observer files are byte-identical across current release audit heads:
storage_cipher_probe.c blob 10a58f670e4d1085e688ad3555b619b3120bad3a and
its header blob 31183ce1b6b4a8c3e32d42346f3420dcff59cbf7. Reviewed all code:
macros wrap the real storage implementation only in the native test target;
observers delegate to real AES and memzero, inspect live objects immediately
after wiping, clear retained observer pointers, and require cipher invocation,
complete wipes and compatible round-trip output. The IV subtraction by 32
returns to a real 64-byte array in each reviewed production caller on all
three products. Native builds include the observer source and link successfully.

Four focused 7.14.3 cipher-cleanup tests pass; earlier full native suites cover
the identical observer on the other products. Marked these two test-harness
files reviewed on each inventory. This is not acceptance of storage format,
cryptographic design, power-loss behavior, or complete storage.c implementation.

Also traced storage_commit's ceremony abort before unrelated writes, its
Bitcoin-only lock check before flash mutation, and terminal shutdown after
exhausted write retries. Wider serialization/migration and fault-path evidence
remain to be completed.

## Bounded 7.14.3 storage-format review

At e298e08a7 implementation (unchanged by 27865aa32 host pin), reviewed the
V16/V17 plaintext, encrypted payload, and ConfigFlash wrapper offsets. Guards
precede reads/writes; wrappers reserve 44 bytes for metadata before passing
the remaining length. Current payload ends at 1501 + 1024 = 2525 bytes. V16
decryption uses its 512-byte legacy encrypted section; production loaders
provide the full storage sector, including for legacy versions. The fixed
plaintext offsets reviewed are inside their conservative 852-byte guard.

read_u32_le promotes unsigned bytes before shifting, avoiding signed-char
extension; write_u32_le extracts individual bytes. Three focused tests pass:
Version17RoundTripPreservesUnsignedFieldsAndAbsentSecrets,
VersionedWritersRejectShortBuffersWithoutWriting, and
VersionedReadersRejectShortBuffersWithoutChangingState. They prove their
named boundary/round-trip properties, not complete format compatibility.

Remaining obligations include migration dispatch and flags, stored-string
termination and consumers, persistence fault behavior, and full cross-product
comparison. The stored language/label arrays are fixed 16/48 bytes; readers
copy that entire width, so termination must be traced through legitimate
writers and corrupted-data handling before closing that scope. No exploit or
new actionable defect is established by this observation alone.

## P03-003: loaded public strings lacked bounds/termination

Current setters zero-fill and use strlcpy for label and supported language,
so legitimately written values reserve a terminator. V11 and V16/V17 readers
instead copied entire 16-byte language and 48-byte label fields after zeroing
those same-size destinations, losing termination for nonterminated stored data.
The legacy reader also copied 17 bytes into its 16-byte language member; the
following has_label assignment overwrote that adjacent byte later, but the
copy itself exceeded its destination member. No host-reachable exploit is
established. GetFeatures is the reviewed consumer; corrupted-data robustness
is the claim, not a demonstrated remote disclosure.

Bound copies to destination size minus one after existing zero-fill, retaining
layout offsets and legitimate setter-produced strings. Regression
VersionedReadersTerminateStoredStrings fails on old 7.14.3 readers for V11,
V16 and V17. Corrected test and all Storage tests pass on each release: 27
(7.14.2), 27 (7.14.3), 34 (7.15), including existing migration fixtures.

Staged fork PRs above frozen predecessors:
- #709, 100f9f2e9, 7.14.2 above 7b26c58dc.
- #710, 7eea5be7b, 7.14.3 above 27865aa32.
- #711, 32df2a9ac, 7.15 above 2b891ceb8.

No format/version change. Combined CI for these new heads remains pending.
Remaining storage migration and persistence review is not closed by this fix.

## Restart-based migration validation

Built current full emulators at 100f9f2e9 / 7eea5be7b / 32df2a9ac and ran
test_storage_version_gate.py with explicit KK_FIRMWARE_ROOT, KK_EMULATOR_BIN
and forced UDP. The suite owns fresh emulator storage and restarts processes;
this is stronger than a same-session RAM-shadow check.

7.14.3 and 7.15 each ran 15 tests: 14 passed, one skipped because their version
ladders contain no burned version. All four runtime cases executed: protected
wallet reboot, V16 upgrade, unknown normal version handling, and Bitcoin-only
band refusal/preservation. Reviewed dispatch routes for normal known versions,
unknown normal versions and the reserved band, including metadata restoration
for the locked state. Unknown normal versions intentionally reset under the
existing downgrade policy; no policy reversal was introduced.

7.14.2's pinned host tree has no test_storage_version_gate.py: discovery there
ran ZERO tests, which is not evidence. Ran the same file from the exact
7.14.3 host checkout ec828d40f7e1f296d52566abcee59c979e562209 against the
explicit 7.14.2 firmware root and emulator instead. Four runtime cases passed;
eleven source-gate cases correctly skipped because 7.14.2 has no declared
STORAGE_VERSION_LAST_SHIPPED floor. Do not count those as passing or imply
that the static gate exists in 7.14.2. Its permanent migration-test coverage
and source-gate disposition remain an integration obligation.

These runs do not establish physical power-loss safety or complete migration
coverage for every historical format. Bitcoin-only runtime migration validation
of the current accumulated heads remains separate work.

### Bitcoin-only migration and future-version preservation

Rebuilt Bitcoin-only emulators at 7eea5be7b (7.14.3) and 32df2a9ac (7.15).
Each storage-version suite ran 15 tests: 14 pass / one no-burned-version skip.
Its own-band branch verifies byte-identical storage across reboot and the same
PIN-protected Bitcoin address. V16 upgrade and normal reboot cases also run.

The existing unknown-version test asserts uninitialized Features, which alone
cannot distinguish wiping from refusal. Do not use its name as proof of flash
preservation on a newer Bitcoin-only stamp. Added a repeatable rehearsal
bitcoin_future_storage.py CHECKOUT BUILD_DIRECTORY: create a protected wallet,
change its banded version to the next version, save the complete image, boot,
assert refusal, halt and compare the entire image byte-for-byte. This passes
on both current Bitcoin-only emulators. No permanent host CI assertion added
yet; the rehearsal is recorded evidence, not a claim that CI checks this case.

This resolves the concrete newer-band preservation evidence gap for these
heads. Physical interruption during a storage write and broader migration
format coverage remain separate obligations.

## 7.14.3 storage declaration changes reviewed

Reviewed include/keepkey/firmware/storage.h and lib/firmware/storage.h changes
at 7eea5be7b. Version 17 floor and reserved base 10000 agree with compile-time
assertions and the migration dispatch. The refusal enum is returned by both
full and Bitcoin-only locked cases and explicitly handled in storage_init;
metadata is restored without committing that wallet. storage_wipe clears the
lock after erasing its sectors. The new staged U2F setter changes only the RAM
counter; the existing persistent setter calls it and then storage_commit.
Declarations match definitions and setup_commit uses the staged form.

Marked these header changes reviewed without actionable findings, supported
by the recorded full/BTC build and restart checks. This is declaration/API
scope, not completion of storage.c or hardware fault-path review.

## P03-004: emulator sector erase is a no-op; migration evidence reopened

All three current release audit trees implement flash_erase_word only under
#ifndef EMULATOR. Emulator writes use memcpy, but erases do nothing. The storage
rotation therefore leaves multiple sectors with valid magic. A migration test
that compares only the original sector can pass after firmware resets RAM and
writes a different sector; restoring the old stamp can resurrect the old wallet.

Confirmed on 7.14.2 head 100f9f2e9, emulator SHA-256
ceb1f31fc49f25db5a6e13e2f83671f6b2b12a8e76c91033016bdcfea6f67b3f.
Instrumented the shared host test: its module, source root, executable and owned
UDP process were correct. After wallet creation both offsets 0x4000 and 0xc000
carried storage magic. Changing the first stamp to 10017 reported uninitialized
and left that original record intact, despite this firmware having no Bitcoin
band refusal implementation. The whole image changed. Its reported preservation
pass was therefore a false positive, not evidence of a supported refusal policy.

The prior runtime migration receipts in this document are withdrawn as release
readiness evidence pending emulator erase correction and serial reruns on all
five release variants. Static source checks remain separate. The earlier
whole-image Bitcoin future-version checks also require rerunning against the
corrected flash model. This finding concerns emulator fidelity; it does not
establish that hardware sector erase is broken. Status: OPEN. Add real emulated
sector erasure and a regression for rotation before trusting reboot tests.

### P03-004 staged correction and replacement evidence

Fork audit units: 7.14.2 PR #712 d59e16cd8; 7.14.3 PR #713 8d08a882d;
7.15 PR #714 c2197307b. Each is based on its frozen stored-string audit branch.
The emulator now fills each selected sector with 0xff using flash_sector_map.
Hardware erase behavior is unchanged. The native regression verifies the whole
selected sector and both surrounding regions; it failed before the correction.
Board suites pass: 19 / 17 / 14 respectively.

With corrected emulators, 7.14.2 ordinary reboot, V16 migration and unknown-version
reset pass. Bitcoin-band preservation now fails, consistent with that release's
absence of the band-refusal feature. This is not counted as a supported test or a
new firmware regression. Both variants of 7.14.3 and 7.15 pass all four runtime
migration tests. The whole-image future Bitcoin-only version preservation probe
also passes on both corrected Bitcoin-only emulators. These replace the prior
false-model receipts for the stated cases only. Wider native and host integration
validation remains pending; no canonical product branch has advanced for this fix.

### 7.15 private storage declarations reviewed

Reviewed lib/firmware/storage.h against the product merge base at c2197307b,
including its additional KDF and retired-identity declarations rather than
inheriting the narrower 7.14.3 header review. Signatures match definitions and
callers. V19 KDF selection is gated off; active unlock/rewrap selects V15/V16,
and V17 decoding clears the V19 flag. The retired two-record identity array has
no production consumers outside the storage scrubber; V18 writing zeros its
910 serialized bytes and reading clears the in-memory array. V18/V19 readers
are not dispatched as current release formats. Existing native retirement,
versioned-flag and PIN serialize/reboot regressions passed in the 504-test full
suite. Declaration review found no actionable issue; complete storage.c and
cryptographic implementation review remain separate open work.

P03-004 broader native validation now passes: 7.14.2 full 158; 7.14.3 full 193,
Bitcoin-only 93; 7.15 full 504, Bitcoin-only 95. All eight reset host tests pass
on both variants of 7.14.3 and 7.15 with the corrected erase implementation.
7.14.2 combined CI is queued at d59e16cd8; 7.14.3 combined CI was dispatched at
8d08a882d. 7.15's older setup-authorization CI remains running, so no redundant
715 dispatch yet. P00 receipt batch was pushed at 341c1052e; superseded doc-only
run 34295681883 is confirmed completed/cancelled.

### 7.14.2 storage header rollback reviewed

Reviewed both storage headers against frozen develop da075b8 at audit head
d59e16cd8. The foundation removes CTAP2/passkey storage, V19 KDF selectors and
Bitcoin-band refusal APIs along with their consumers; searches of production
and native-test sources found no remaining references to the removed APIs or
fields. The private header restores the V15/V16 boolean KDF signatures used by
its definitions/callers. The storage ladder ends at 17 and the public header
explicitly reserves alpha formats 18/19/20. The downgrade from those formats or
Bitcoin-only storage is a reset in this foundation, not preservation; corrected
emulator evidence above now reflects that policy. This does not establish an
upgrade path from those later formats or audit the separate release-history gate.

The U2F stage/set distinction matches implementation: reset stages the counter
before its authorized setup commit; public set persists immediately. LoadDevice
and ApplySettings set the counter after other settings have been staged and have
no subsequent rejection gate before final commit. Both header declaration deltas
have no actionable findings; implementation and consumer reviews remain scoped
separately, and this receipt does not close the complete P03 phase.

### Setup test and recovery declaration review

Reviewed complete setup_ceremony.cpp at d59e16cd8 / 8d08a882d / c2197307b.
7.14.3 and 7.15 files are identical (SHA-1 8fd7d46448accda17ec33eda254607c013247ba2);
7.14.2 differs only by lacking the two recovery-fragment cases and their include.
Fixture initialization enables real failure dispatch and aborts between tests.
Tests cover stage collision, idempotent abort, generated mnemonic cleanup,
wrong-kind continuation, pre-arm inertness, both ceremony permutations, and
aborted/wrong-kind commit rejection. The 240-byte mnemonic observation fits the
pinned crypto implementation's 240-byte static mnemo buffer. Additional recovery tests
use debug-only fill/zero observers for the actual recovery buffers. Native logs
confirm 7 / 9 / 9 cases passed; the latter logs contain binary bytes and require
text-mode searching. These tests do not prove flash persistence or every wire
interleaving, as their coverage comment explicitly states. No test delta needed.

Recovery public headers were read completely: all three differ only in the two
extra debug-only observer declarations in 7.14.3/7.15; signatures and reset/abort
ownership match definitions. No actionable declaration issue. Also reviewed the
7.14.2 storage_versions.inc rollback: entries 1..17 preserve their positional
values, LAST(17) matches the public version, and macro cleanup remains intact.
Reserved later format policy is documented in the public header; no reader for
18/19/20 is claimed. These bounded file reviews do not close P03 as a whole.

### Passphrase cancellation review across all variants

Read the complete passphrase_sm.c state machine. All three release files are
identical (SHA-1 88b02f6ffdd700f05fe19ac69fdc6f0d9d1db565). The local tiny-message
buffer, confidential passphrase state and escaped display buffer are scrubbed;
passphrase caching happens only after successful confirmation. Escape capacity
is four bytes per input byte plus terminator and uses checked output bounds.
Owned-emulator rehearsal passed on all five variants at the emulator-erase heads:
Cancel and Initialize at entry and at confirmation, followed by another protected
Ping that must request the passphrase again. Cancel returns Failure; Initialize
returns Features. No cached passphrase or stale terminal response was observed.
General transport-error unwind interactions remain a separate open obligation.

## P03-005: current PIN and wipe-code stack buffers are not scrubbed

All three pin_sm.c files are identical (SHA-1
91ac357e834ee395679213235595636404ba31f2) at d59e16cd8 / 8d08a882d / c2197307b.
Code tracing confirms pin_request decodes credentials into caller-owned PINInfo.
pin_protect returns from cancellation, wipe-code detection, invalid PIN and
success without clearing its local PINInfo. change_wipe_code likewise returns
without clearing either entry. change_pin_staged already uses a common cleanup
exit, but that does not cover these paths. Existing tiny-buffer cleanup removes
the transport copy only. This is residual credential material, not an established
remote extraction primitive. Status OPEN: extend local credential cleanup to all
returns and validate normal PIN, cancellation, mismatch and wipe-code flows.

### P03-005 staged remediation

All three functions now route returns after credential entry through memzero of
the complete local PINInfo structures. Current PIN paths preserve their previous
result and counter behavior; wipe-code entry clears both attempts on cancellation,
mismatch and success. The no-PIN fast path never creates credential state.
Fork units: PR #715 e33fa4a00 (7.14.2), #716 374efb1b6 (7.14.3),
#717 b73f7a5f7 (7.15), each on its frozen emulator-erase predecessor.

All five existing PIN-change host tests pass on all five emulator variants after
rebuilding. This verifies behavior, not stack residue directly; complete exit
cleanup was checked in source. Wipe-code entry is behind ENABLE_WIPECODE in the
normal handler, so no enabled wipe-code runtime coverage is claimed. ARM and
combined integration evidence remains pending. Finding status: fixed in audit
units, awaiting final validation and canonical assembly.

### PIN entry rejection and declaration review

At PIN-cleanup heads e33fa4a00 / 374efb1b6 / b73f7a5f7, an owned-emulator
rehearsal passed on all five variants: empty, zero and alphabetic PIN matrix
acknowledgements return PinCancelled; Cancel returns PinCancelled; Initialize
returns Features. After each, another protected Ping requests the PIN again,
and a correctly encoded PIN succeeds. This verifies input rejection, cache
behavior and terminal reply ordering. It does not directly observe erased stack
bytes or prove every transport-error interleaving.

Read the remaining PIN request/validation/decode code: bounded protobuf copy,
1..9 digit validation before matrix indexing, checked index conversion, matrix
masking on return, and tiny-buffer clearing are present. PIN declarations in
7.14.3 and 7.15 are identical (SHA-1 dd75cc6128b6622f1505c56030f567d681c155a3).
Their added change_pin_staged contract matches the implementation and its setup
caller, which passes the full PIN_BUF capacity and requires staged state.
No actionable header issue. PIN implementation remains in progress for the
recorded cleanup integration and broader transport/error interactions.

## P03-006: 7.15 previous-word display scratch retained seed text

At b73f7a5f7, next_character formats a completed recovery word into static
prev_info[32]. Only byte zero is reset on the next draw; the buffer was neither
confidential nor scrubbed at return/abort. The separate last_completed_word
cleanup did not clear this display copy. The previous-word feature is absent
from 7.14.2 and 7.14.3, confirmed by comparing complete recovery source deltas.
This is residual seed-word text, not a demonstrated remote extraction primitive.

Fix staged in fork PR #718, f8c5692b3, above frozen PIN-cleanup predecessor:
mark the buffer CONFIDENTIAL and memzero it immediately after layout_cipher.
The renderer reads the text synchronously and retains only the separate cipher
pointer for animation, so clearing the text does not invalidate its rendering.
Normal recovery with and without PIN/passphrase passed on both 7.15 emulator
variants. Source review establishes cleanup; host tests establish behavior, not
direct residue observation. Combined ARM/integration validation remains pending.
Broader recovery review, including backspace and cross-phase interactions,
remains in progress.

### Recovery input behavior after the current cleanup units

Four existing host cases passed on all five variants: invalid character,
backspace over the entered phrase followed by re-entry, known word-count
validation (0..12), and unknown-count terminal failure followed by rejected
continuation. Heads: e33fa4a00 / 374efb1b6 / f8c5692b3. This supplements normal
recovery checks; it does not prove previous-word display accuracy during every
backspace sequence or every transport-error interaction.

CI 34297216508 completed successfully at 7.14.2 emulator-erase head d59e16cd8,
and 34295830100 completed successfully at 7.15 setup head 8ac4bd9df. Neither
contains every current fix. New combined validation was dispatched for
7.14.2 PIN-cleanup and 7.15 recovery-display-cleanup. Artifact inspection and
canonical integration remain pending. 7.14.3 emulator-erase validation is still
running and was not restarted.

Recovery source comparison also shows that 7.14.2's debug-only auto_completed_word
is not included in recovery_cipher_reset, unlike 7.14.3/7.15. Its actual
post-abort behavior requires a bounded follow-up before declaring recovery
cleanup complete. Keep this associated with P03 recovery-buffer lifetime review;
no whole-file completion claim is made from the passing behavior tests above.

## P03-007: 7.14.2 debug recovery word survives cancellation

Owned-emulator reproduction at e33fa4a00: enter synthetic word "all", observe
successful autocomplete, Cancel, then query recovery_auto_completed_word. It
still returned "all" after the terminal Failure. recovery_cipher_reset omitted
this debug-only buffer. This is the follow-up previously recorded in the recovery
comparison, now confirmed rather than inferred.

Fork PR #719 c593bdbd7 clears the buffer under DEBUG_LINK in the shared reset
path. The same regression passes after the fix. Unchanged full 7.14.3 374efb1b6
and 7.15 f8c5692b3 pass the control; both already clear the buffer. Non-debug
builds contain neither this buffer nor its DebugLink accessor. Status: fixed in
bounded audit unit, combined validation/canonical assembly pending. No claim
that ordinary production USB exposes this debug-only field.

### Recovery helper and passphrase-transition test review

Reviewed recovery.cpp completely: three cases verify prefix versus exact match,
precise/unique/invalid autocomplete, and every word's padding through index 8.
The autocomplete test's nine-byte array accommodates the longest eight-letter
BIP39 word plus NUL; comparisons use the actual array extent. The file is
identical across release worktrees (SHA-1 afe2f1672ca38099e47071791a2600688d359617),
and only 7.14.2 includes it in the changed-path inventory. Its native cases passed.

Reviewed complete storage_passphrase.cpp on all three products (identical SHA-1
badeb57d1f379f417167d453d1a779a5388674a1). Setup initializes emulator storage and
loads the synthetic fixture; teardown aborts setup and clears session state.
Expected wallet private key and chain code are independently derived from the
fixture phrase and chosen passphrase. Five cases cover enable, disable, unchanged
setting, retained PIN authorization and retained staged setup. All five executed
in each recorded full native suite. These tests prove RAM wallet selection and
specified retained state, not reboot persistence or UI confirmation. Source and
subject code are unchanged by the subsequent PIN/display/debug cleanup units.
No actionable findings in these bounded test-file reviews.

Corrected an earlier receipt's generated mnemonic capacity: bip39.c declares
mnemo[24 * 10], not 256 bytes (the latter belongs to a different cache field).
The existing 240-byte cleanup observation remains valid and exactly spans mnemo.

### Setup storage-boundary coverage added

Fork units #720 132db57da (7.14.2), #721 1f97ea58c (7.14.3),
#722 2e1c67e9e (7.15) add StagingIsInertAndForeignCommitAborts using the existing
storage-backed PassphraseTransition fixture. It verifies original active label,
passphrase protection and PIN state remain unchanged after staging/arming;
a foreign storage_commit disarms the ceremony, retains those active settings,
and prevents stagePin/rearm from reviving the discarded staging state.

All six PassphraseTransition cases pass on all five release variants. This
adds direct boundary coverage missing from the setup-only cases; it does not
prove every staged field, every wire ordering, or physical fault tolerance.
Reviewed the test's preconditions and postconditions and updated the obsolete
comment claiming firmware-unit cannot initialize flash. Firmware behavior is
unchanged. Combined CI and canonical integration remain pending.

### Reset header and release-specific API review

Reviewed complete reset.h and compared all three release variants at audit tips
132db57da / 1f97ea58c / 2e1c67e9e. Shared setup declarations match staging,
arming, abort and the newly authorized bool-returning commit implementation.
7.14.2 has no dice parameter; 7.14.3 adds dice and rejects its combination with
display_random; 7.15 removes display_random from the internal API while retaining
and ignoring the wire field. Handler argument order matches each signature.
Dice digest access returns 0 or copies 32 bytes to the debug response field and
its state is cleared by setup_abort; this does not audit dice entropy quality.

7.15 alone declares shared mnemonic display scratch. Array dimensions match
definitions in confidential storage and the reset/BIP85 consumers; consumers
explicitly clear the arrays around use. Header review establishes declaration
and ownership consistency, not complete BIP85 or paging behavior. These three
header reviews have no remaining actionable findings; reset implementation and
cross-phase display/transport obligations remain open.

Superseded documentation run 34297193569 is now confirmed completed/cancelled.
Current documentation run is 34298090688 at pushed 0ff5a1aea; subsequent local
review receipts are being accumulated for the next batch publication.

### Reset entropy and backup control-path review

Reviewed 7.15 reset_init/reset_entropy and compared the 7.14.3 deltas, then
checked 7.14.2's initialization and distinct early-exit path. Strength accepts
128/192/256; setup is staged before prompts and armed only before EntropyRequest.
No-backup requires two confirmations and still passes through setup_commit's
live-kind gate. SHA256 combines 32 device bytes with the provided host bytes;
mnemonic generation uses the validated strength. Device entropy is cleared after
conversion. The backup page index is checked immediately after increment and
before access; fixed buffers bound formatting and each accepted path uses the
same authorized commit. Page buffers are cleared at exit. 7.15 additionally
clears its BIP85-shared scratch at entry. Return-to-home clears constant-power
mode through layout_clear_static.

7.14.2 retains but ignores display_random and has no dice path; 7.14.3 retains
the optional entropy display but excludes dice/no-backup combinations; 7.15
has removed that display. Random-source correctness and dice mixing remain
separate P09 obligations. An apparent missing SHA context cleanup on 7.14.2's
backup-warning cancellation was dismissed after inspecting its pinned
sha256_Final: it memzeros the whole context before returning. No extra patch.

This review found no new actionable defect in these control paths. Existing
P03-001 remediation and reset/PIN/dice host receipts remain supporting evidence.
Whole-flow handling of unexpected tiny messages and BIP85/display interactions
remain open; these bounded findings do not mark the full phase complete.

### PIN/passphrase file review closure with staged transport remediation

The complete PIN and passphrase state-machine implementations have now been
read and their changed behavior reviewed across all products. The files share
the same implementation across releases. PIN input validation precedes matrix
indexing; cancellation resets the matrix; cached and uncached paths retain
existing authorization behavior. P03-005 clears local current-PIN/wipe-code
credentials on return. Passphrase confirmation gates caching and clears input
and escaped display scratch. Neither recognizes unrelated acknowledgements as
authorization. Terminal tiny receive rejection now unwinds both through the
P02-006 receive latch rather than continuing after Failure.

Mark these six file reviews reviewed_fix_staged, referencing P03-005 and
P02-006, not accepted integration. Host checks cover normal PIN changes,
invalid PIN input, Cancel/Initialize, passphrase confirmation cancellation,
and fresh requests after malformed/unknown tiny messages across five variants.
Wipe-code entry remains disabled in the release handler; no enabled-feature
runtime claim. Physical fault/timing properties and complete caller behavior
remain separate phase obligations.

Latest full native suites pass with P02-006: 7.14.2 159, 7.14.3 194,
7.15 505; Bitcoin-only suites pass 94 and 96 respectively. Combined CI was
dispatched for 7.14.2 534ac50a9 and 7.14.3 f342d5a73 after their previous runs
completed. 7.15's older recovery-display CI remains active; no duplicate dispatch.

### Recovery implementation review: autocomplete and remaining edit-state boundary

Read the complete 7.15 `recovery_cipher.c` at cb5650490 and compared it with staged 7.14.2 / 7.14.3 implementations. Autocomplete initializes all 2049 permutation entries, permutes only the first 2048 (leaving the wordlist sentinel last), bounds padded comparisons to the BIP39 maximum, and clears its permutation on every post-acquisition return. The 7.15 frame-arena scratch acquisition resets inbound assembly; the lookup itself neither polls USB nor emits messages, so this reviewed call path does not overlap an outbound encoding. Previous releases use dedicated static permutation storage. This bounded review found no actionable defect in that lookup lifetime.

The four existing recovery input cases (invalid character, backspace/re-entry, known word-count rejection, unknown-count failure followed by stale input rejection) pass on the full 7.15 terminal-rejection implementation, no skips; `/private/tmp/715-terminal-recovery-inputs.log`. This is protocol evidence, not evidence of previous-word screen accuracy.

Remaining 7.15 edit-state review is explicit: deleting a word separator changes the current word index while `last_completed_word` is updated only on forward boundaries/reset; the previous-word indicator needs targeted observation when moving backward across multiple word boundaries. The backspace comment also assumes a fixed session cipher even though `next_character()` reshuffles it per character; the reconstructed `coded_word` heuristic needs separate verification. Neither concern is closed by the successful generic backspace test. Full recovery file status remains in progress pending these checks and final integration.

### P03-008: 7.15 previous-word indicator stale after deleting a separator

Confirmed with an owned emulator on cb5650490: enter `all `, save the top-left indicator pixels, enter `zoo `, then delete the last separator. The indicator for the preceding word should return to `1.all`; its pixels differ because `last_completed_word` still contains `zoo`. The corrected rehearsal fails before and passes after 1ead40605. An initial harness invocation used an unsupported third assertEqual argument; that invocation is not counted as defect evidence.

Fix on `audit/715-p03-recovery-backspace-display`: when deleting a separator, clear and reconstruct the previous completed word from the edited mnemonic, autocomplete its stored prefix, and scrub scratch. No corresponding display feature exists in 7.14.2/7.14.3. Full 7.15 emulator: targeted indicator regression 1 pass and existing recovery input suite 4 passes, no skips. Logs `/private/tmp/715-previous-word-before.log`, `715-previous-word-after.log`, `715-backspace-display-inputs.log`. Repeatable runner: `rehearsals/recovery_previous_word.py CHECKOUT BUILD_DIRECTORY`. Bitcoin-only execution, broader recovery regressions, exact-head CI and canonical integration remain pending. The separate cipher-heuristic edit-state concern remains open.

P03-008 validation extension at 1ead40605 (fork PR #726): rebuilt Bitcoin-only emulator. Expanded the retained screenshot-region regression to cross back into word 2, cross again into word 1 (indicator cleared), and move forward (indicator restored). Full and Bitcoin-only both pass, no skips: `/private/tmp/715-previous-word-expanded.log` and `715-btc-previous-word-expanded.log`. Normal recovery commit with and without PIN/passphrase also passes on both variants, two cases each: `715-backspace-recovery-commit.log` and `715-btc-backspace-recovery-commit.log`. The screen assertion compares the top eight pixel rows of the leftmost 72 columns, outside the cipher animation; it does not claim complete screenshot equivalence or validate unrelated screen text. Exact-head CI and canonical integration remain pending.

### 7.15 public storage header review

Read `include/keepkey/firmware/storage.h` in full, blob c5fc45e066381b68f4efcac619ef4ec940581eff. Compared against the already reviewed 7.14.3 header: only explanatory comments differ; declarations, constants, types and conditional declarations are identical. Version 17, shipped baseline 17 and reserved Bitcoin-only band 10000 remain enforced by storage.c static assertions. The lock API corresponds to the runtime flag accessor. The reflashing comment describes a compatible Bitcoin-only reader, not a promise that an older reader can load a future storage format. No actionable declaration/constant difference found; close this header's inventory entry. This does not close storage.c or prove all storage migration paths.

### Storage test review: policy lifetime and Bitcoin-only migration assertions

Reviewed the 7.15 policy tests (reset/set, AdvancedMode writer bit suppression, V11/V16/V17 reader suppression, stale-bit update status, attacker-named legacy policy, session-clear policy lifetime), normal legacy migration fixture, Bitcoin-only band tests, short-buffer and cipher cleanup assertions. Policy tests establish positive preconditions and use RAII to restore global AdvancedMode after assertions. The stale-bit fixture distinguishes clean SUS_Valid from dirty SUS_Updated; it does not itself exercise flash commit durability. Short-buffer writer tests check the full sentinel buffer on refusal and trailing bytes on accepted capacity; reader tests check unchanged destination state. Cleanup assertions use the previously reviewed real-cipher observer. Remaining storage.cpp sections are still pending full review.

Evidence gap: `BitcoinOnlyBandMigrates` required only a result other than SUS_BitcoinOnlyLocked for older/current versions. SUS_Invalid could pass. Tightened it in 77f50c016, fork PR #727, to require SUS_Updated / SUS_Valid respectively plus the Bitcoin-only stamp in the decoded storage. The future-version refusal stays asserted. The strengthened test passes; complete Bitcoin-only Storage suite passes 34 cases (`/private/tmp/715-btc-migration-storage-suite.log`). This is a regression-test correction, not a reproduced firmware migration failure. Canonical integration remains pending.

### 7.15 storage test file review closure

Completed the remaining sections of `unittests/firmware/storage.cpp`, blob e98eda06225bf272c8035e813974be27ca90f334: metadata/cache byte fixtures, legacy read/decrypt/re-encrypt, debug node serialization, fixed-byte V16 serialization oracle and reload, no-secret encryption early return, policy upgrade helper, PIN/wipe-code wrapping, legacy unhardened-wrap upgrade, reset key rotation, retired identity block, V19 flag isolation, and V17 PIN serialization/reload. `NoopSecMigrate` initializes the fields its early-return path reads; storage_secMigrate returns before session/key access when encrypting without secrets. The V17 reboot test uses fresh RAM structures, rejects an incorrect PIN, recovers the original storage key with the correct PIN, and decrypts the expected mnemonic. It models serialization/reload, not physical flash writes or power interruption. The retired-identity test checks both zero serialization and rejection/scrubbing of attacker-filled records. The V19 gate remains disabled in this release; the gated positive branch is not counted as executed coverage.

Full and Bitcoin-only Storage suites each pass 34 tests at the staged assembly: `/private/tmp/715-storage-review.log` and `715-btc-migration-storage-suite.log`. Close the test file as reviewed with the PR #727 assertion correction staged; this closes test-source review, not production storage.c or complete migration coverage. CI 34297894523 succeeded on the older f8c5692b3 assembly. Latest assembled head 77f50c016273512fa20321179b9746cc60876717 is running as CI 34299583518; exact-head acceptance remains pending.

### 7.14.2 / 7.14.3 storage test review closure

Compared complete test bodies across all three releases. 7.14.2 and 7.14.3 storage.cpp test bodies are equivalent apart from ordering/declarations. Compared their shared bodies with the reviewed 7.15 file; differences are the older boolean KDF interface, legacy policy expectation, version-byte fixture spelling, buffer capacities, and absence of 7.15-specific tests. Reviewed the additional unsigned-field/absent-secret round trip: it checks high-bit bytes in two uint32 fields and false secret/authentication flags after V17 serialization. The 2600-byte short-buffer fixtures fit the V11/V16/V17 tested lengths; these versions lack the larger retired identity layouts.

Found a reset-test argument alias: sca_hardened was passed twice, rather than passing v15_16_trans independently. Corrected in 02349bf77 (7.14.2, PR #728) and 8ef50c146 (7.14.3, PR #729). Production code is unchanged. Storage suites pass 27 each on 7.14.2 full, 7.14.3 full and Bitcoin-only: `/private/tmp/7142-storage-flags-test.log`, `7143-storage-flags-test.log`, `7143-btc-storage-flags-test.log`. Close both test-file reviews with the corrections staged, not canonically integrated. Full production storage review remains pending; these native tests do not establish hardware power-loss behavior.

### Production storage commit review: open power-interruption boundary

Read 7.15 storage_init/reset/wipe/session-clear/commit and the active-sector selector. Compared commit ordering with both 7.14 releases and frozen develop da075b8cb717b56dc1023edb52c2ccdf171b8a08. All three staged releases erase the active sector, advance to another sector, erase it, then write data and magic. A power interruption after the first erase and before replacement magic can leave no active wallet record. Their memory.c selector picks the first sector with storage magic. Frozen develop instead retains the active record while building a replacement and includes generation/trailer/boot-marker coordination. Thus the release rollback removes a storage durability mechanism present in the comparison base; this is not covered by green RAM serialization or normal reboot tests.

Keep this cross-file issue OPEN pending a fault-injection rehearsal and a compatibility-aware resolution. Simply moving the old-sector erase later is insufficient: two valid records can coexist after interruption, while the release selector has no generation ordering and boot protection uses neighboring sectors. Review must include storage.c, memory.c, metadata/trailer format and bootloader selection, preserving the intended V17 compatibility contract. No physical power-cut experiment has been performed, and no partial ordering patch was applied. Existing successful commit checks cover aligned 2572-byte CRC including the final encrypted byte, retry bounds, temporary-buffer scrub, and fail-closed shutdown after exhausted retries. The Bitcoin-only commit refusal is checked before flash writes and after foreign-ceremony revocation. Full production storage remains in progress.

### Durability remediation source and extraction boundaries

Located prior implementation aa88b996a3900721163f474a05c7596fdbefc668 (already in frozen develop). It combines three concerns: U2F staging, PIN salt creation, and crash-recoverable commits. Do not wholesale cherry-pick it into the V17 releases. The durability subset spans keepkey_board.h metadata padding/framing constants, memory.h declarations, memory.c active/pending validation and finalization, storage.c metadata serialization/generation/init/commit, and board regression cases. The emulator erase behavior is already corrected in the current audit stacks.

The prior record format uses formerly padded metadata bytes 41..43 as a 24-bit generation, keeps Storage at offset 44, CRC-covers 2572 payload bytes, and appends an 8-byte marker/CRC trailer. The V17 adaptation must retain its existing writer and version stamp, assert unchanged offsets, and preserve Bitcoin-only refusal. Existing board tests cover legacy selection, newest generation, wraparound, corrupted replacement fallback, pending invisibility, torn final magic, and corrupt pending rejection. These are candidate regression sources, not yet executed against a release adaptation. The implementation preserves old record+boot marker while writing the spare sector; only a verified replacement permits retirement, marker installation, and final magic. Failed finalization keeps the pending replacement for boot recovery and must never call storage_wipe. Bootloader behavior and fault injection across each transition remain required before accepting the port.

### V17 durability prototype started on 7.15

Local branch `audit/715-p03-durable-v17-storage`, commit 1af100d23, ports only the record-framing/recovery subset from frozen develop. V17 serialization remains unchanged; the commit envelope inserts the generation into former metadata padding and appends CRC framing. Updated active/pending selection, initialization recovery and replacement-first commit ordering together. Removed the obsolete erase-first sector-shift helper. The inherited board fixture now restores its prior emulator flash pointer instead of replacing it with nullptr.

Full native build succeeded; eight StorageSelection cases and 34 Storage cases pass. Owned-emulator normal recovery commits with and without PIN/passphrase also pass (two cases). Logs `/private/tmp/715-durable-v17-build.log`, `715-durable-selection.log`, `715-durable-storage.log`, `715-durable-recovery-commit.log`. This is a local prototype, not accepted remediation: full commit fault injection, legacy bootloader compatibility, Bitcoin-only refusal/recovery, ARM resource checks, and propagation to 7.14.2/7.14.3 remain pending. No canonical release changed.

Durability prototype 1af100d23 validation extension: Bitcoin-only build completes; StorageSelection 8/8 and Storage 34/34 pass (`715-btc-durable-build.log`, `715-btc-durable-selection.log`, `715-btc-durable-storage.log`). Bitcoin-only normal recovery with/without PIN/passphrase passes two cases (`715-btc-durable-recovery.log`). Existing `TestStorageUpgradePreservation.test_reboot_preserves_the_wallet` passes without skips on both full and Bitcoin-only emulators (`/private/tmp/715-durable-reboot.log`, `715-btc-durable-reboot.log`): current-version stamp, unchanged full flash image during boot, initialized/PIN-protected state and identical derived Bitcoin address are asserted. This establishes ordinary persistent reboot behavior only. Version-mutating migration fixtures must account for the new CRC trailer before their results can be interpreted; changing just a version byte now creates a corrupt framed record rather than a valid alternate-version fixture. Interruption/bootloader compatibility and cross-release propagation remain open.

Durability handoff test added to the local 7.15 prototype: `StorageSelection.HandoffKeepsLegacyBootProtectionDisabled` models the legacy first-magic selector plus adjacent protection marker across all three starting sectors. It checks old-record selection while the pending replacement is written, no active record after retirement, pending discovery/finalization, and protection status after removing the retired marker. Nine StorageSelection cases pass (`/private/tmp/715-durable-handoff.log`). The initial test build failed on C++ enum increment; corrected to explicit allocation iteration and rebuilt successfully. An eight-case output from the stale binary after that failed build is not counted as new evidence. This test models completed flash operations using the real erase/recovery helpers; it does not interrupt actual storage_commit or execute an installed bootloader, so those requirements remain open.

Durability prototype published as draft fork PR #730 above #727, head 90be3e937. Bitcoin-only selection/recovery now passes all nine cases (`/private/tmp/715-btc-handoff.log`); full board suite passes 23 cases (`715-durable-board-all.log`). The draft explicitly retains actual-commit fault injection, valid-CRC migration/refusal fixtures, installed-bootloader compatibility, ARM resource checks and cross-release propagation as incomplete acceptance work. 7.14.3 transport CI 34299145628 succeeded; latest test-flag branch CI dispatched separately. No canonical release ref changed.

CRC-framed migration rehearsal retained as `rehearsals/framed_storage_migration.py CHECKOUT BUILD_DIRECTORY`. It wraps the existing fixture patch method, requires the framing marker, and recomputes CRC-32/MPEG-2 over little-endian 32-bit payload words after each fixture edit. It does not change firmware parsing or weaken existing wallet/address/state assertions. Three cases pass without skips on each 7.15 durability variant: normal reboot, synthetic V16 migration, and Bitcoin-only band behavior (full refuses, Bitcoin-only accepts its own band). Logs `/private/tmp/715-framed-migration.log` and `715-btc-framed-migration.log`. These edited V16 fixtures retain valid new framing; authentic unframed V16 legacy migration and future in-band refusal still need explicit checks. The helper assumes the created fixture has one active sector; it does not model generation selection among multiple records.

Migration rehearsal extension: `framed_storage_migration.py` now also constructs an unframed V16 fixture by restoring zero metadata padding and erased trailer after the existing V16 layout conversion. Both variants pass that migration while retaining the known wallet/address assertions. Added a valid-CRC future-version fixture: Bitcoin-only refuses and preserves the entire image; full firmware follows its existing unknown-version reset policy and changes the image. Final five-case suite passes without skips on both variants (`/private/tmp/715-framed-complete.log`, `715-btc-framed-complete.log`). These are synthetic fixtures derived from a real committed wallet, not archived hardware flash dumps. Full commit interruption testing and installed-bootloader execution remain open.

Actual-commit boundary rehearsal implemented locally: emulator-only weak flash-operation observer snapshots the image after every completed erase/write helper call during storage_commit. A strong native-test observer records seven images. `PassphraseTransition.WalletSurvivesEveryCompletedCommitOperation` restores each image, reinitializes storage, checks initialized state and old-or-new label, and derives the expected wallet using the existing independent mnemonic/HD-node oracle. Full seven-case PassphraseTransition suite passes in an isolated fresh working directory (`/private/tmp/715-commit-snapshots-suite.log`). An initial run in the shared worktree captured zero writes and failed the snapshot-count assertion; it is not accepted evidence. The fresh-directory run proves seven actual commit boundaries, not partial word/erase interruption or a complete CPU/bootloader restart. Bitcoin-only execution and further fault cases remain pending. Observer code is absent from non-emulator builds.

Commit replay now passes on full and Bitcoin-only 7.15: all seven operation-boundary images plus three partial final-magic byte prefixes recover the expected wallet. The three torn images are constructed between real snapshots 4 and 5; the test locates the sector whose magic changed, asserts it exists, and programs one/two/three bytes before reinitialization. Seven-case PassphraseTransition suites pass on both (`/private/tmp/715-torn-magic.log`, `715-btc-torn-magic.log`). Emulator observer declaration/calls are all preprocessor-excluded from hardware builds; no ARM execution claim follows from that source check. Partial payload writes, partial erases and installed-bootloader execution remain unverified. Changes pushed to draft #730.

Actual-commit replay expanded to six partial replacement payload prefixes: 1, 4, 512, 1500, 2568 and 2575 bytes, the last one byte short of the 2576-byte payload/trailer write. Images are constructed from actual pre/post-write snapshots; each must retain the old label and derive the expected wallet after storage_init. Both full and Bitcoin-only seven-case PassphraseTransition suites pass (`/private/tmp/715-partial-payload.log`, `715-btc-partial-payload.log`). The replay now checks 16 images per variant: seven completed-operation boundaries, three torn final-magic prefixes and six partial payload prefixes. This is sampled payload interruption coverage, not every bit/byte cut or partial-erase physics. Changes pushed to draft #730; cross-release propagation and ARM acceptance remain pending.

7.14.3 durability port started on local `audit/7143-p03-durable-v17-storage` above #729. Initial full build succeeded but three pending-selection tests failed. Root cause: its emulator calc_crc32 consumed word_len bytes with reflected CRC semantics, unlike hardware and the pending-record CRC. Ported 7.15's hardware-compatible emulator implementation; hardware branch unchanged. Rebuilt: all nine StorageSelection cases pass, and 27 Storage plus seven PassphraseTransition cases pass, including 16 commit replay images (`/private/tmp/7143-durable-selection.log`, `7143-durable-storage.log`). This validates the full emulator only so far; Bitcoin-only build, host migration, ARM and 7.14.2 propagation remain pending. The initial failure is retained as evidence of the CRC prerequisite rather than counted as a storage-protocol failure.

7.14.3 durability head e25201c6f now validated on both emulator variants. Bitcoin-only selection/recovery 9 passes and Storage/PassphraseTransition 34 passes, including the 16-image commit replay (`/private/tmp/7143-btc-durable-selection.log`, `7143-btc-durable-storage.log`). Full and Bitcoin-only migration rehearsal each pass five cases (`7143-durable-migration.log`, `7143-btc-durable-migration.log`), no skips. Changed C files pass clang-format validation. Port published as a draft above #729; ARM/CI, installed-bootloader and partial-erase acceptance remain open. 7.14.2 still requires its own port.

7.14.2 durability port published as draft #732, head 75be71abc, above #728. Its existing version policy is retained; no Bitcoin-only lock was introduced. Build, nine StorageSelection tests and 34 Storage/PassphraseTransition tests pass, including 16 replay images (`/private/tmp/7142-durable-build.log`, `7142-durable-selection.log`, `7142-durable-storage.log`). Four migration/reboot cases pass (`7142-durable-migration.log`), using the 7.14.3 test module on PYTHONPATH because the 7.14.2 host pin lacks it; firmware root/binary and keepkeylib remain explicitly bound to 7.14.2. Runner KK_TEST_BAND=0 excludes only the inapplicable band test. An initial import failure executed no tests. Changed C files pass formatting. All three durability ports now exist as draft fork PRs #730/#731/#732, but ARM/CI, bootloader and partial-erase acceptance remain open; canonical releases have not advanced.

CI progression: 7.14.2 test-flag run 34299743827 and 7.14.3 test-flag run 34300006521 completed successfully. Dispatched CI on their durability drafts #732/#731 after those lanes became terminal. The preceding 7.15 run 34299583518 remains active, so its durability CI has not been stacked concurrently. Verified tools/bootloader/main.c invokes storage_protect_wipe(fi_defense_delay(storage_protect_status())) before selecting update/normal boot. This source check confirms why the adjacent marker is mandatory; it does not substitute for execution against an installed bootloader. Partial erase behavior, particularly transition from a legacy record without CRC to a framed replacement, remains an explicit unresolved fault scenario.

Confirmed durability-draft defect: a modeled partial erase of an unframed old record can preserve `stor` while setting a label bit; storage_init selected that legacy record and ignored the complete pending replacement. The 17th snapshot case fails before correction (`/private/tmp/715-legacy-torn.log`, corrupted label) and passes afterward with the full seven-case PassphraseTransition suite (`715-legacy-torn-after.log`). Local 7.15 correction finishes a verified pending handoff when the selected active record has an erased legacy trailer; verified active records retain the existing path. Recovery failure preserves data and shuts down. This case models a 0-to-1 erase bit change and checks the committed replacement label; it is not a physical erase experiment. Bitcoin-only validation, broader regression and propagation to the 7.14 drafts remain pending.

Torn-legacy correction propagated and pushed to all durability drafts: 7.14.2 63037ea11 (#732), 7.14.3 108329282 (#731), 7.15 b9b88955f (#730). Seven-case PassphraseTransition suites pass on all five variants, including the 17-image replay and replacement-label assertion for the damaged legacy record. New logs: `/private/tmp/715-btc-legacy-torn.log`, `7142-legacy-torn.log`, `7143-legacy-torn.log`, `7143-btc-legacy-torn.log`; full 7.15 previous receipt is `715-legacy-torn-after.log`. These are source/build-specific local receipts; existing CI runs on predecessor heads do not validate the correction. No canonical branch advanced.

Predecessor ARM evidence inspected for 7.14.2 durability run 34300623966: downloaded artifact `firmware-v7.14.2-75be71a` to `/private/tmp/7142-durable-arm`. All 23 files match their manifest SHA-256 entries; manifest binds firmware 75be71abc3ce31a0d7cf654c6aa7733ebcba987b and host d3b26aee636d6d203fd91e988d1b273c4971a3ab. Firmware ELF SHA-256 e07fd9db236e67f881c427817d5574d90cb3574a754a0a232e1a5e04c8922348. Symbol inspection confirms find_pending_storage/recover_pending_storage are linked and emulator_flash_operation_completed is absent. ARM build succeeded; overall run still active when checked. This predecessor predates the torn-legacy correction and is not current-head acceptance.

Current durability-head full native regression: 7.14.2 63037ea119d52ba9ceccd47b86b87a73380b9a7f passes 160 firmware tests; 7.14.3 1083292820bc52dffafc14e7ce88258946fc2a00 passes 195 full and 95 Bitcoin-only; 7.15 b9b88955fa4ea137e882189764394f3c5a5ed198 passes 506 full and 97 Bitcoin-only. Each executable ran serially from a fresh temporary working directory. Logs `/private/tmp/7142-durable-full-native.log`, `7143-durable-full-native.log`, `7143-btc-durable-full-native.log`, `715-durable-full-native.log`, `715-btc-durable-full-native.log`. The first sandboxed 7.15 attempt stopped at a denied UDP bind and is not a test receipt; the permitted complete rerun passed. Current-head CI runs 34309591609 (7.14.2), 34309716891 (7.14.3), and 34309719051 (7.15) remain in progress. Predecessor durability runs 34300623966 and 34300625891 completed successfully, but do not accept the correction.

Coverage reconciliation: reopened durability-touched files, including previously reviewed storage_passphrase.cpp, for the current remediation delta. Paths absent from the historical frozen inventories are explicitly tracked in staged_remediation_additional_paths without changing the historical comparison counts. Existing reviewed_blob values retain their historical meaning and do not certify the new heads. ARM/resource, bootloader handoff and remaining production storage review are still open; no canonical branch advanced.

Current-head 7.14.2 ARM receipt: CI run 34309591609 completed successfully at 63037ea119d52ba9ceccd47b86b87a73380b9a7f. Artifact firmware-v7.14.2-63037ea downloaded to `/private/tmp/7142-durable-current-arm`; all 23 SHA-256 entries verify. Manifest binds the exact firmware head and host d3b26aee636d6d203fd91e988d1b273c4971a3ab. Firmware ELF SHA-256 is 56dab939a0410f9ab3fdb8f254c6ce7d32a2dad28ff3e2b3e148799023c3037e. Symbols confirm pending recovery is linked and the emulator snapshot hook is absent. `_ebss=0x2001a014`, `_stack=0x2001f7f8`: static RAM-to-stack reserve 22,500 bytes, above the 16 KiB floor; this is not a measured worst-case runtime stack bound. This closes the current-head 7.14.2 ARM build/artifact check only, not remaining storage or full-release acceptance.

### P03-009 — durable framing invalidated host migration fixtures

Origin: integration regression introduced by the staged durable-commit envelope. The 7.14.3 and 7.15 pinned test_storage_version_gate.py modified version/flags/ciphertext bytes without refreshing CRC framing. Reproduced the unmodified V16 migration case against 7.15 b9b88955f: it failed the initialized-wallet assertion (`/private/tmp/715-current-original-migration.log`). The fixture was rejected as corrupt before the intended version reader; this is not evidence that a valid legacy V16 wallet is lost. The separate framed_storage_migration.py runner already corrected framing, but that did not repair the checked-in host suite.

Host fix preserves an optional crc1 envelope during fixture edits, adds an unframed V16 migration case, and compares the whole flash image after band stamping and before/after locked boot. Unknown Bitcoin-only versions explicitly preserve the image; unknown full-product versions retain the existing reset policy. All five cases pass without skips on both variants of 7.15 and 7.14.3. Logs `/private/tmp/715-current-fixed-migration.log`, `715-btc-current-fixed-migration.log`, `7143-current-fixed-migration.log`, `7143-btc-current-fixed-migration.log`. Emulator binaries were rebuilt from the torn-legacy corrected firmware before testing. Synthetic V16 conversion remains a compatibility fixture, not an archived hardware dump.

Staged host PRs BitHighlander/python-keepkey #86 (6268e38) and #87 (5dae186), based on their preceding dice-test branches. Firmware dependency-only drafts #733 (0307ca0ae, 7.15) and #734 (450851b72, 7.14.3) target durability predecessors #730/#731. No canonical release or develop changed. 7.14.2 host d3b26ae lacks this module; its explicitly cross-root four-case rehearsal remains separate evidence and is not represented as checked-in host coverage. Current-head CI/build provenance for the changed pins remains pending; do not carry predecessor manifests forward as exact-head receipts.

Recovery heuristic follow-up: next_character() randomizes cipher after each key, but recovery_delete_character() reconstructs coded_word using the current cipher and describes it as session-fixed. This does not reconstruct the historical wire characters. The decoded mnemonic remains independently restored from mnemonic. Impact on the plaintext-entry heuristic is still unverified and requires a targeted behavioral reproduction; do not close it based on successful previous-word indicator tests.

Migration-runner provenance correction: importing a borrowed test_storage_version_gate module can prepend that helper checkout to sys.path, defeating the earlier caller's library precedence. Updated framed_storage_migration.py to restore the selected import path after helper import and assert keepkeylib resolves under the requested release checkout. Earlier cross-root receipts lacking that assertion are not proof of the claimed host-library pin. Re-ran the four 7.14.2 cases on current d4c23c9d5 successfully with the asserted d3b26ae library path (/private/tmp/7142-current-pinned-migration.log). Same-root 7.14.3/7.15 fixture runs did not borrow another checkout. This corrects evidence attribution rather than firmware behavior.

### Released bootloader 2.1.4 binary replay

The historical upstream v7.3.2 blupdater.bin contains the released 2.1.4 payload
at offset 0x3204, length 262144. Updater SHA256:
6bb7cfd28262fcd61c450fdc3f6932650bdf16a134ab6c1bc6f90b0d1578e620.
Payload double-SHA256 fe98454e7ebd4aef4a6db5bd4c60f52cf3f58b974283a7c1e1fcc5fea02cf3eb
matches bl_hash_v2_1_4 in the firmware, unlike the newly built candidate bootloader.
Source asset: https://github.com/keepkey/keepkey-firmware/releases/tag/v7.3.2.

Disassembly identifies storage_protect_status at 0x0802363c, its calls to the real
legacy selector (0x08023510), next-sector helper (0x08023560), and memcmp
(0x0802a914), and storage_protect_wipe at 0x080236ac. The repeatable
rehearsals/bootloader_storage_gate.py executes these unmodified ARM Thumb routines
using pinned Unicorn 2.1.4. It intercepts only flash_erase_word at 0x08022790 to
observe requested sectors rather than simulate peripheral registers. Both routine
returns are checked against a sentinel PC with time/instruction limits. Input
payload identity and exact snapshot count are enforced.

799 controls pass: factory-empty; active wallet with valid/missing marker in all
three sectors; each of the 264 bits in the 33-byte marker (including terminator)
corrupted independently in each sector. Invalid controls must request erasure of
all three storage allocations [2,3,4]; positive controls must preserve storage.
All 17 actual-commit/sample-interruption images pass per build on 7.14.2,
7.14.3 full/BTC and 7.15 full/BTC. Seven PassphraseTransition native cases pass per
build while exporting the fixed-test-wallet snapshots. No host-owned wallet or
physical device is involved. Machine-readable snapshot hashes and verdicts are
in rehearsals/evidence/bootloader-214/{7142,7143,7143-btc,715,715-btc}.json.

Snapshot exporter is opt-in test-only code: #748 (7.14.2 c1f33fcbb, followed by
predecessor-header merge 6bf2f396e), #746 (7.14.3 330556334), #747 (7.15 e8fe34811).
Normal unit runs create no export files; production code/pins are unchanged.
This closes the named 2.1.4 storage-protection decision-logic gap for sampled
commit states. It does not execute reset/startup, the fi_defense_delay peripheral
path, other released bootloader binaries, actual flash erases or exhaustive torn
writes. Broader supported-bootloader applicability and physical release checks
retain explicit dispositions; no whole-storage-phase acceptance is inferred.
