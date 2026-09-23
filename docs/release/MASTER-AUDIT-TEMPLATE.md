# Firmware release audit — master template

This file in the **main firmware worktree** is the canonical audit form for all
agents. For a 7.15 unit, read it with `docs/release/REHEARSAL-SOP.md` before
opening an isolated audit worktree. Copy this form into the unit's report source
and fill every section. Keep the unit report in `docs/release/audit-units/` and
render its PDF from that source. A separate worktree may contain a snapshot of
this template; the main worktree copy is the coordination reference. Record the
main template commit or, while the main worktree has uncommitted changes, its
SHA256 in the unit receipt so agents can detect drift.

## 1. Identity and frozen scope

- Unit/block and owner: `<ID>` / `<owner>`
- Audit worktree and branch: `<absolute path>` / `<branch>`
- Live PR URL, exact base branch and SHA, exact final head SHA: `<...>`
- Candidate source branch and SHA; canonical release branch and SHA: `<...>`
- Dependency/submodule paths and exact pins: `<table>`
- Included historical unit commits and explicitly withdrawn units: `<table>`
- Selected invariants, scope exclusions, and release gates: `<...>`

## 2. Git line inventory and plain-language changes

Use `git show --format= --numstat --no-renames COMMIT_SHA` for **each** historical
unit and relevant later interaction. For each commit, list its files, additions,
deletions, prior behavior, changed behavior, why it matters, and regression or
validation evidence. Identify test, documentation, and submodule-pointer lines.
Do not sum overlapping commit counts as a net candidate diff.

Create report files, commit them, then regenerate the report against an immutable
`BASE_SHA..REPORT_PREDECESSOR_SHA` range. Include every PR file, including the
report source and binary PDF (`-`/`-`). Commit the regenerated report. Confirm
`git diff --numstat BASE_SHA..FINAL_HEAD_SHA` has the same paths and counts, or
explain any exact difference before review. Put the containing final SHA in the
PR body. Never cite a mutable branch, `HEAD`, or a one-argument `git diff` as
reproduction evidence.

| Group | Commit or range | Files | Added | Deleted | Plain-language description and evidence |
| --- | --- | ---: | ---: | ---: | --- |
| Original unit | `<SHA>` |  |  |  |  |
| Later interaction | `<SHA>` |  |  |  |  |
| Review PR | `<BASE>..<PREDECESSOR>` |  |  |  |  |

## 3. Current-source reconciliation and findings

Trace each retained behavior through the **current candidate**, not merely the
historical unit commit. Record every finding as fixed, refuted, accepted
limitation, or pending, with a technical reason and exact source/test evidence.
Keep inherited open risks and withdrawn work visible; do not describe them as
fixed or waived. Distinguish unknown-version policy, variant-specific policy,
and test-only changes when applicable.

## 4. Verification and artifact identity

| Check | Source/head or image ID | Command/run | Result | Artifact ID/SHA256 | Skips/limits |
| --- | --- | --- | --- | --- | --- |
| Focused regression |  |  |  |  |  |
| Full native and board |  |  |  |  |  |
| Bitcoin-only native and board |  |  |  |  |  |
| Host/emulator power cycle |  |  |  |  |  |
| ARM/SRAM and release gates |  |  |  |  |  |

State exactly which CI run matches code, tests, pins, workflows, and report
head. Earlier firmware-equivalent CI is supporting evidence, not an exact-head
workflow pass. Name every skipped test and separately identify any later run
that closes the gap. Record physical-device checks still required.

## 5. Report render and local preflight

- [ ] Source report and PDF contain the same inventory and findings.
- [ ] PDF pages were opened and checked for legibility.
- [ ] Live target base still matches the recorded base.
- [ ] Final Git diff matches the report file inventory and numeric counts.
- [ ] Exact source, predecessor, final head, pins, skips, and open risks agree
      across report, scope receipt, and PR body.
- [ ] `git diff --check` passes and PR files belong to this unit.
- [ ] Preflight result, command outputs, and artifact identities are recorded.

## 6. Copilot checkpoint and completion

Use **one** request after the local preflight. If it finds issues, read the body
and every inline comment, fix the set in one batch, document dispositions,
recheck the entire report, and spend at most one corrective request without a
new owner decision. Record request count, review IDs, and reviewed SHAs.

A delivered review on the **current final head** with `Findings: None`, zero
inline findings, and zero unresolved threads completes the Copilot checkpoint.
A generic overview such as “Needs a closer look” does not negate this result
unless it states a concrete actionable body-only finding; quote and disposition
any such item. A pending, stale, failed, or quota-limited review is not clean.
Keep local audit completion separate from physical-device and release promotion
gates. Once the checkpoint and unit evidence pass, mark the unit complete and
move to the next block without buying an extra confirmation review.
