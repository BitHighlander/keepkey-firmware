# Firmware release audit — master template

This file in the **main firmware worktree** is the canonical audit form for all
agents. For a 7.15 unit, read it with `docs/release/REHEARSAL-SOP.md` before
opening an isolated audit worktree. Copy this form into the unit's report source
and fill every section. Keep the unit report in `docs/release/audit-units/` and
render its PDF from that source. A separate worktree may contain a snapshot of
this template; the main worktree copy is the coordination reference. Record the
main template commit or, while the main worktree has uncommitted changes, its
SHA256 in the unit receipt so agents can detect drift.

## 7.15 audit progress (not release approval)

- **Block 00a — complete for the audit-unit checkpoint (2026-09-22).**
  [PR #844](https://github.com/BitHighlander/keepkey-firmware/pull/844)
  targets fork `develop` at `fc1e93746132553ad98ed60f4847c8d770732bf9`;
  final head `9cb72384fd14b2a688a70d17711a7923941d2290`, tree
  `8f3be92b55df9a5582f4fb4669bad65416ae16ae`. Its adjacent diff is
  19,986 changed lines. Exact-head hosted run
  [35810605413](https://github.com/BitHighlander/keepkey-firmware/actions/runs/35810605413)
  passed required jobs; emulator publication was intentionally skipped. Local
  full/Bitcoin-only Docker, ARM, OLED and companion checks are recorded in the
  [unit report](https://github.com/BitHighlander/keepkey-firmware/blob/9cb72384fd14b2a688a70d17711a7923941d2290/docs/release/audit-units/715-00a-release-foundation.md).
  Current-head Copilot reviews `5286304890` and `5286389477` both say
  `Findings: None`, with zero inline findings and zero unresolved threads, which
  satisfies the explicit checkpoint rule in the SOP. Their generic “Needs a
  closer look” overviews remain a human-review note, not a concrete finding.
  This completes Block 00a only; it does **not** approve the assembled 7.15
  release, physical-device testing, merging, or publication.

| Block | Audit-unit checkpoint | Final review evidence | Remaining release limits |
| --- | --- | --- | --- |
| P01 | **Pending phase integration.** The five P01 unit notes report local fixes or checks, but do not contain a completed phase receipt. | `audit-units/P01-001-manifest-application.md`, `P01-004-report-inputs.md`, `P01-006-disassembly-input.md`, `P01-007-build-arguments.md`, and `P01-008-compose-variant.md` | Do not infer P01 completion from P02 ancestry or the Block 00a product checkpoint. |
| P02 / Block 2 | **Complete for the audit-unit checkpoint.** [PR #850](https://github.com/BitHighlander/keepkey-firmware/pull/850), final head `92f3d00f2b75c1fe02ba3a00a7ea46b4e163c31e`; [receipt](audit-units/P02-final-review-20260922.md) and [report](audit-units/P02-audit-report-20260922.pdf). | Copilot review `5285534015` on that head: `Findings: None`, zero unresolved threads. Its generic evidence-traceability overview names no new actionable item; six prior inline findings are recorded as resolved. | F161 and F204 remain accepted test limitations; hardware and exact later workflow certification remain separate gates. |
| P03 / Block 3 | **Complete for the audit-unit checkpoint.** [PR #851](https://github.com/BitHighlander/keepkey-firmware/pull/851), final head `5b5a9c1b196f82a6a98e07f6ba2729560aeafe89`; [scope and owned-emulator receipt](audit-units/P03-block-scope-20260922.md) and [report](audit-units/P03-audit-report-20260922.pdf). | Copilot review `5285845557` on that head: `Findings: None`, zero unresolved threads. Its generic artifact-traceability overview names no new actionable item; the prior inline inventory finding is resolved. | The inherited erase-before-replacement power-interruption risk remains open and outside this block; physical recovery and exact later workflow acceptance remain release gates. |
| P04 / Block 4 | **Complete for the audit-unit checkpoint.** [PR #852](https://github.com/BitHighlander/keepkey-firmware/pull/852), final head `92931c91dc77bf2cdf80aaa8938b978add0cfde8`; [scope and evidence](audit-units/P04-block-scope-20260922.md) and [report](audit-units/P04-audit-report-20260922.pdf). | Copilot review `5285987088` on that head: Approved, `Findings: None`, zero inline findings and zero unresolved threads. Two earlier documentation findings are resolved. | Physical signing/OLED review, signed-device upgrade, and exact later workflow acceptance remain release gates. |
| P05 / Block 5 | **In progress** on `audit/715-p05-final-review`, based on P04. The owner selected inference from candidate history; [scope and executed host evidence](audit-units/P05-block-scope-20260922.md) cover Zcash viewing-key consent and account identity. | No final report or review receipt yet. | Full and Bitcoin-only variant outcomes, remaining handler coverage, physical checks, and exact workflow limits must be reported before completion. |
| P06 / Block 6 | **In progress** on [PR #853](https://github.com/BitHighlander/keepkey-firmware/pull/853), currently based on P04 because P05 is outside that unit. | Scope and owned-emulator Ripple evidence are in the PR; its report, PDF, and final review remain pending. | Do not count it complete or treat its current head as a P05 receipt. |

These entries record audit-unit completion, not release approval. Their source
candidate is `audit/715-scope-repair @ 614425a2a14d0113de251e7944118e47f31f5265`;
the canonical `release/7.15` product and fork `develop` were not advanced by
P02–P04. Recheck the live heads before relying on this ledger.

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
