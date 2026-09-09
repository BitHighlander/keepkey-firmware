# Internal release acceptance control

Updated 2026-09-09 after B02 integration. This document defines remaining gates;
it does not assert a fresh remote or CI verification. Follow
[REHEARSAL-SOP.md](REHEARSAL-SOP.md). Finding details and coverage remain in the
[phase ledgers](PHASED-AUDIT-COVERAGE.md); exact product and audit identities are
in [RELEASE-PROGRAM.md](RELEASE-PROGRAM.md).

## Current milestone and restart record

Primary milestone: internally accept canonical 7.14.2. Follow with 7.14.3
Bitcoin-only and 7.15. Shared-fix applicability remains required across all three.
All three are auditing; none is internally accepted or ready for Copilot.

Current execution checkpoint (owner scope correction supersedes B02):

- [x] Remove bootloader-coupled durability from candidates #754 / #755 / #756.
- [x] Fresh native firmware/board and full pinned-host suites pass all five variants.
- [x] Restore shared storage selectors and metadata to pre-durability identities.
- [ ] Exact-head CI/ARM validation: 34416605044 / 34416675343 / 34416677172.
- [ ] Integrate validated corrections into canonical products with forward commits.
- [ ] Complete remaining release-wide coverage and shared-consumer review.
- [ ] Resolve the original power-interruption finding within authorized scope or
      obtain an explicit release disposition; do not claim it fixed.

Bootloader audit expansion is excluded. Historical replay evidence cannot create
new acceptance requirements. See [scope-repair.md](audit-coverage/scope-repair.md)
for withdrawn receipts, retained findings and exact candidate identities.

## Per-release gates

Unchecked means not yet established by a complete acceptance receipt. Record a
receipt link in a cell when that gate passes; partial evidence stays in the ledgers.

| Gate | 7.14.2 | 7.14.3 Bitcoin-only | 7.15 |
| --- | --- | --- | --- |
| Frozen feature scope, comparison base, head and pins reconciled | Pending | Pending | Pending |
| Every current changed path/hunk has supported review disposition | Pending | Pending | Pending |
| Dependency deltas and cross-phase interactions reviewed | Pending | Pending | Pending |
| No unresolved actionable findings or required evidence gaps | Pending | Pending | Pending |
| Applicable shared findings dispositioned across all three products | Pending | Pending | Pending |
| All accepted shipping fixes integrated into canonical branch | Pending | Pending | Pending |
| Required native/host/ARM/resource/storage/UI checks pass on final candidate | Pending | Pending | Pending |
| Skips, artifact hashes, provenance and supported variants verified | Pending | Pending | Pending |
| Canonical remote head matches validated tree and receipt | Pending | Pending | Pending |
| Internal acceptance receipt complete; external gates listed separately | Pending | Pending | Pending |

Determine required checks from shipped behavior and existing manifests. Do not
silently drop an established variant or check. Physical OLED, signed-upgrade and
other external release gates must have explicit applicability and stage recorded.
If a physical check is required to establish an internal safety invariant, missing
hardware evidence blocks that invariant; an emulator pass does not substitute.
External-only publication checks do not imply authority to flash, sign or publish.

## Integration batch receipt

Record the following in the existing candidate/unit receipt locations:

- Release, canonical starting SHA, candidate head/tree and exact dependency pins.
- Included accepted unit IDs/SHAs and any intentionally excluded product content.
- Dependency order, conflict resolutions and reviewed interactions.
- Required checks with executed/skipped results, run IDs and artifact identities.
- Remaining release findings and coverage, without implying this batch closes them.
- Verified canonical remote SHA after update; open product PR still targets develop.

A validated batch can update a canonical release while other audit phases remain
open. It must not introduce or worsen unresolved defects, and unresolved product
findings remain visible. This is integration progress, not internal acceptance.

## Checkpoint and overnight handoff format

For each product report:

1. Canonical head and audit tip, explicitly identifying uncommitted work.
2. Closed/current total coverage from the reconciled ledger, or “not reconciled.”
3. Unresolved finding IDs and required evidence gaps; link their dispositions.
4. Accepted units awaiting integration and the next assembly batch.
5. Validation on the named candidate: passed, failed, running, skipped or not run.
6. Next concrete acceptance milestone and any blocker with its resolving action.

Record progress as acceptance items closed and canonical integrations completed.
Do not call a release “done” because fixes were pushed or test counts increased.
When all gates pass, state “internally accepted; awaiting external review” with
exact receipts. Copilot, upstream submission, develop merging and publication
remain outside this internal run.
