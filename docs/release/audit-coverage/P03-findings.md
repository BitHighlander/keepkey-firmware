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
