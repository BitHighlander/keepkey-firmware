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

## P03-002: dice reset test duplicates a debug backup word group (open)

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
