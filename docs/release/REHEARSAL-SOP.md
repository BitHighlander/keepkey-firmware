# Firmware rehearsal and acceptance SOP

Owner decision: 2026-09-07. This is the canonical procedure for the new
7.14.2 hardening foundation and subsequent extraction of alpha features.
It supersedes the alpha audit requirement for two whole-tree zero-finding
passes as a prerequisite to staging. Historical rehearsal handoffs are
evidence, not executable instructions or current branch identities.

## Firmware-only scope boundary

Owner correction, 2026-09-09: bootloader changes are out of scope. Neither the
"perfect" audit goal nor a firmware finding authorizes a bootloader redesign,
new storage-protection contract, bootloader release, or bootloader audit program.
Trace consumers of shared code before accepting a change; directory names alone
are not a scope check. A shared storage change that alters bootloader selection
or protection is excluded unless the owner separately changes scope.

For a firmware fix that crosses this boundary, record the confirmed finding and
separate the proposed remediation. Preserve the existing storage/bootloader
contract, or remove the coupled batch from these candidates. Do not add bootloader
work as a new release acceptance requirement to justify the expansion. Existing
compatibility evidence can remain historical evidence, with its actual limits;
it does not authorize bootloader changes. Independent firmware changes in shared
files still require consumer-impact review; this correction is not blanket
acceptance of all shared-library changes.

The 2026-09-09 durability batch is withdrawn from the corrected release candidates.
See [scope-repair.md](audit-coverage/scope-repair.md) for exact predecessors,
removed scope, retained findings and current validation. No whole-release or
bootloader-artifact equivalence follows from restoring that batch.

## Two fork PR types: products and audit units

Owner clarification: 2026-09-08. The main products are the fork release branches
for 7.14.2, 7.14.3 and 7.15. Small rehearsal branches are the workspace for
hardening and feature extraction before accepted changes update those products.
All internal PRs live in the fork. Neither PR type is merged into fork develop.

| PR type | Head and target | Purpose and acceptance |
| --- | --- | --- |
| Release product | Main fork release branch → fork `develop` | Cumulative, buildable product candidate with a release manifest, exact pins, accepted-unit receipts and complete product checks. Its large diff is an integration view, not a request to rediscover every issue on every iteration. |
| Audit unit | Isolated rehearsal branch → fork `develop` when independent; otherwise → its immediate predecessor | One bounded behavior or defect, reviewed and tested locally against its recorded base. Dependent units stay stacked and unmerged into develop. |

Both types belong to the fork-develop staging program; a dependent audit PR
must target its predecessor so its review diff stays small. Do not retarget all
stack members directly to develop and recreate the cumulative review surface.
The existing F00–F05 stack is rehearsal evidence, not the complete 7.15 product.

For each release, record its canonical branch, frozen source SHA, intended
variant and required features in `RELEASE-PROGRAM.md`. Branch naming alone does
not establish that a source is accepted or that two release branches are equal.

1. Select a named gap in the product manifest and freeze its source and base.
2. Extract or harden it on small audit branches. Complete the local contract
   below before recording a unit as accepted.
3. Assemble accepted units on an isolated integration candidate based on the
   recorded product head. Resolve interactions there, preserving existing product
   content unless an omission is explicitly recorded. A conflicted replay or an
   interaction defect returns to a named audit unit for local validation.
4. Validate the assembled product, including required release variants and exact
   dependency pins. Record the included unit SHAs and resulting tree in a receipt.
5. Update the canonical fork release branch to the validated candidate, keeping
   its product PR into develop open and unmerged. Check that the remote product
   head still equals the recorded base; if it moved, reconcile and validate again.
   Prefer a normal fast-forward update; do not silently reset or force-push it.
6. Realign remaining rehearsal branches onto the accepted product or their updated
   predecessor. Assess the changed diff and affected interactions, carrying forward
   valid evidence for unchanged code. Repeat for the next named gap.

Updating a fork release branch is internal product assembly, not a develop merge,
an upstream submission, or release publication. A product is ready only when its
entire declared scope passes; accepting individual units alone is insufficient.

## Full-release review gate

Owner correction, 2026-09-08: assembled branches and passing CI are prerequisites,
not completion of the requested audit. For each product, freeze its fork develop
comparison base, merge base, product head and dependency pins. Inventory every
changed path, including deletions, generated sources, dependencies and automation.
Partition the actual PR surface into bounded phases. Record reviewed files/hunks,
security and behavior invariants, concrete findings and their dispositions, and
cross-phase interactions. Unread paths remain pending even when tests pass.

Use inherited review evidence only when its exact source and scope are recorded.
Review remediation deltas and affected interactions until no actionable findings
remain. Do not mark a release ready for the final Copilot checkpoint until every
phase and the assembled interaction audit is complete. Keep the goal active until
all three release products meet this gate. This does not authorize Copilot or
merges into develop.

## Convergence and acceptance control

Operational revision: 2026-09-08. Use
[RELEASE-ACCEPTANCE-CHECKLIST.md](RELEASE-ACCEPTANCE-CHECKLIST.md) as the live
control record. This section governs scheduling and status; it does not waive
full-release coverage or authorize external actions.

Work toward one primary release milestone at a time: first internal acceptance
of 7.14.2, then 7.14.3, then 7.15. Continue applicable shared-fix ports while their
context is fresh. Do not add alpha features beyond the frozen 7.15 manifest.
This order is a scheduling priority, not permission to omit another product.

Keep at most one discovery unit and one assembly batch active. Before opening
another discovery unit, finish the current unit or record its concrete blocker
and switch to named independent work. A unit's size is determined by one behavior,
its invariants and affected consumers, not an arbitrary line-count target.

At every completed phase or three accepted units for the primary release,
whichever occurs first, assemble and validate the accepted batch before opening
more unrelated discovery. At session start, reconcile any existing backlog that
already exceeds this threshold. Do not replay an unaccepted predecessor merely
to reach an accepted descendant. Extract onto the canonical base and validate,
or name the blocking dependency and finish it first. If assembly is blocked,
record the exact blocker and next resolving action; independent work may continue.
The cadence is an integration checkpoint, not a release-acceptance shortcut.

Use these distinct statuses and never abbreviate all of them to “done”:

| Object | Status progression | Required evidence |
| --- | --- | --- |
| Audit unit | scoped → reviewing → staged → accepted | Named contract, exact base/head, reviewed delta and interactions, finding dispositions and applicable checks. Pushed or green alone means staged. |
| Integration batch | assembling → validated → integrated | Included accepted units, exact tree/pins, interaction review, required checks, then verified canonical remote head. |
| Release | auditing → internally accepted → awaiting external review | Complete current scope coverage, no unresolved actionable findings, integrated fixes and final candidate validation. External review remains a separate phase. |

“Blocked” is an additional condition with a reason, not an acceptance status.
A finding fixed on an audit branch is “staged remediation”; it is not resolved
in the canonical product until integrated and verified there.

Close a unit after its contract is satisfied. Reopen only for a concrete new
failure, a changed invariant or requirement, a dependency/consumer change that
invalidates its reasoning, or evidence that required coverage was missing or
incorrect. Record the trigger and affected scope. A new reviewer, another elapsed
round, a changed unrelated head or optional cleanup is not a reopening reason.
Carry forward exact unchanged evidence with an explicit impact assessment.

Triage each candidate finding as confirmed defect, unverified claim, missing
required evidence, optional improvement, or technically rejected. Confirmed
in-scope defects and missing required evidence prevent internal acceptance.
Unverified claims need a bounded reproduction or source-trace task and disposition;
they must not silently become either fixes or accepted risks. Optional improvements
leave the frozen scope. Do not relabel a defect optional to meet a deadline.

If two consecutive remediation rounds do not close a finding or acceptance item,
stop repeating the same review. Record the obstacle and choose a smaller unit,
a targeted experiment, or a root-cause investigation. This is an escalation of
method, not a cap that permits unresolved defects to pass.

## Autonomous session contract

Verify the execution goal is active before promising unattended continuation.
A paused app goal is an execution-control blocker, not a firmware acceptance
result. If available tools cannot resume it, tell the owner that the app control
needs resuming, preserve the current checkpoint, and continue authorized work
within the current turn. Never claim an overnight worker is running from a
written plan or a paused goal.

Before an overnight run, record the primary milestone, exact starting heads,
current unit, required checks and known blockers in the acceptance checklist.
Use the existing ledgers as the finding source of truth; link rather than copy
finding details into new reports. Firmware changes must address a named defect
or frozen product requirement. Host, tooling and documentation work must name
the firmware check or acceptance item they enable.

At each integration checkpoint and at handoff, report canonical head versus audit
tip, coverage closed/total from the current ledger, unresolved finding IDs,
accepted-but-unintegrated units, exact validation status, and the next milestone.
Label historical receipts and tests run before local uncommitted changes.
PR counts and test counts are supporting evidence, not release progress measures.
Do not invent a percentage when the current inventory has not been reconciled.

Continue authorized internal work without per-unit permission requests. Preserve
dirty unrelated work. Do not merge develop, request Copilot, submit upstream,
flash hardware, sign or publish releases under this internal audit contract.
When a required check cannot run, name the missing evidence and continue useful
independent work; do not waive the check or claim internal acceptance. Finish an
accepted milestone by advancing to the next release. Finish all three by issuing
an exact acceptance handoff and leaving the external checkpoint pending.

## Foundation first

Use the current audited 7.14.2 candidate as the selected foundation. The
initial immutable identity is recorded in `7.14.2-HARDENING-MANIFEST.md`.
Selection does not claim that this head has passed final acceptance.

Create a fresh rehearsal branch from that SHA. Do not merge alpha into it.
Existing shared develop remains preserved until the replacement is proven.
The proposed foundation is represented by an unmerged PR into fork develop.
Do not merge or reset develop under this rehearsal authorization. Alpha feature staging may proceed on the tested foundation PR before release acceptance; dependent units remain unmerged.
Promotion of a shared branch is a distinct recorded operation; this procedure
does not silently reset, force-push, merge upstream, or publish a release.

## Define a finite batch

Before editing code, record the base, source commits, exact dependency pins,
selected behaviors, affected security invariants, acceptance checks, exclusions,
and actual dependency order in a versioned manifest. Never select a moving
branch name as the sole source identity.

For the foundation, scope is defects in existing 7.14.2 behavior and validation
needed to prove their fixes. New chains, new alpha features, unrelated cleanup,
and storage-format redesign are excluded. A necessary scope change must be
recorded explicitly, with its impact on the batch and acceptance evidence.

Triage known audit findings before commissioning new broad discovery. A claim
about alpha must be reproduced or traced on the selected 7.14.2 head before it
becomes foundation work. Do not infer reachability from a shared filename.

Before replaying a historical fix, compare it with the current product's explicit
policy and later implementation. Record it as present, applicable and missing,
superseded, or excluded with a technical reason. A historical commit calling
something a vulnerability is evidence to investigate, not permission to reverse
the current contract. Check test build registration and version-based skips against
the actual candidate capabilities; a test in the tree is not evidence it ran.

Before closing a finding, record its applicability to all three canonical
products at exact heads: present and verified, applicable and staged, or
excluded with a technical reason. Include any corresponding regression test
and whether it actually runs in full and Bitcoin-only configurations. Reuse
existing proven fixes where policy matches. A fix present in 7.15 does not
close the same root cause in 7.14.2 or 7.14.3.

## Findings and review units

Each finding has a stable ID, affected SHA/configuration, concrete failure
trace or reproduction, impact, origin (existing defect or introduced regression),
disposition, and regression evidence. Deduplicate by root cause. Missing
verification is unverified, never confirmed or refuted. Reviewer votes alone
are not proof. Record technical reasons for rejected findings.

One unit addresses one independently explainable behavior with its tests.
Author coherent commits; use separate PRs for independently reviewable units.
Do not hide many unrelated units inside a single large PR. Preserve relevant
prior audit fixes and evidence when extracting code; review extraction changes.

A new finding blocks the unit if it introduces, worsens, or depends on that
defect. A confirmed critical defect in the shipping candidate blocks release
even if outside the current unit. Other unrelated findings receive a separate
disposition and batch assignment; they do not silently expand this batch.

## Local rehearsal to convergence

Owner revision: 2026-09-08. Continue using Codex for implementation and local
review. Copilot is deferred to late upstream/release phases and is not an
internal staging acceptance gate. This revision supersedes earlier mandatory
per-PR clean-Copilot requirements and review-round ceiling blockers.

“Perfect” means the frozen unit meets its written acceptance contract with no
known unresolved in-scope defects. It is not a claim of zero possible bugs or an
instruction to keep inventing improvements. Define the finish line before work.

1. Inventory existing findings, deduplicate root causes, and pin baseline/source
   identities. Define the behavior, invariants, affected consumers and checks.
2. Implement a coherent unit. Review its actual diff against its predecessor,
   including dependency changes, bounds, failure paths, state lifetime and tests.
3. Batch concrete findings into scoped fixes. Reproduce defects where practical;
   add regression coverage that distinguishes incorrect from correct behavior.
   Run format/build checks before review so mechanical nits do not consume rounds.
4. Repeat local review of the remediation delta and affected interactions until
   no actionable in-scope findings remain. Every additional iteration must name
   the defect or missing evidence it resolves. Do not restart whole-alpha audits.
5. Freeze the candidate. Run required unit, integration, ARM/resource and storage
   compatibility checks; inspect skips, screenshots and artifacts where required.
   Reconstruct the stack and verify its tree, dependency pins and source provenance.
6. Record a candidate receipt: exact head/base, completed checks and local review,
   finding dispositions, exclusions and remaining release-only requirements.
   A passing candidate ends the internal loop. Advance to the next unit.

Before dispatching the expensive combined CI matrix, finish the capability/skip
inventory and pass the local native, host, and report-validator suites. A focused
unit pass is not that preflight. Use small local checks while reconciliation is
still changing the candidate; do not repeatedly launch a full matrix and cancel
it for the next known unit. Receipt-only documentation changes may carry forward
validated code/pin evidence when their non-documentation diff is proven empty.

A review pass is not evidence of correctness by itself. Do not weaken tests,
remove required coverage or redefine behavior merely to obtain a clean result.
Confirmed release-critical defects still block release. Optional style preferences
and unrelated improvements go to a separate backlog rather than reopening a
passing candidate. A recurring finding requires root-cause analysis or a smaller
unit, not additional unchanged review prompts.

## Copilot only at the late external checkpoint

Do not request Copilot during authoring, local hardening, predecessor propagation,
or routine fork PR staging. Do not create a PR or push solely to trigger Copilot.
Quota exhaustion, missing delivery or a historical round ceiling does not block
internal work or acceptance under the local contract above.

The final upstream SOP includes Copilot audits on the frozen, upstream-shaped
fork PRs before creating upstream PRs. This is the owner's selected late checkpoint;
it does not authorize requests during the current internal rehearsal phase.
Enter it only after the release and its proposed upstream units pass internal
acceptance and the upstream submission phase begins. Audit the small final units
and their affected interactions; do not substitute a broad product diff for them.
Never automatically start a repeat-until-silent Copilot loop. If findings arrive,
triage and fix them locally in a batch; a re-request needs a concrete reason tied
to that external checkpoint. Preserve prior dispositions and review counts.

A failed, missing or quota-limited review is not a clean review. Report Copilot's
actual status separately from internal readiness. Existing substantive findings
must still be resolved or explicitly declined on technical grounds; deferring
Copilot does not waive known defects or any upstream-required review gate.

## Final upstream SOP

1. Select an accepted release receipt and pin the live upstream target. Prepare
   the final small PR sequence on fork branches, recording source units and public
   dependency availability. Account for every intended product change or explicitly
   record what is deferred from this upstream batch.
2. Reconcile upstream-base differences locally and rerun affected checks plus the
   required assembled-candidate checks. Freeze the exact proposed heads and bases.
3. Perform final Copilot audits on these fork PRs before creating upstream PRs.
   Batch actionable findings into local fixes and revalidate. Record review IDs,
   head SHAs and technical dispositions. A quota failure is pending, not clean;
   continue independent local work but do not claim this checkpoint passed.
4. Record the final audit outcome honestly. The target is a delivered review with
   no actionable findings on the final candidate; any declined finding retains its
   rationale and must not be reported as a literal “no findings found” response.
   Material changes after review require an impact assessment and refreshed audit
   coverage before the checkpoint is considered complete.
5. Create upstream PRs from the validated sequence with concise behavior, provenance
   and test evidence. Upstream merging and release publication remain separate
   operations. Never merge the fork product PR into develop as a prerequisite.

## Evidence and invalidation

Record base/head SHAs, submodule IDs, check/artifact links, actual executed and
skipped tests, local review scope/result, dispositions, and acceptance status.
Record external review identities when available without making them implicit gates.
Retain completed review reasoning for unchanged surfaces. Reopen it when code,
dependencies, or new evidence invalidate that reasoning. A changed head needs
an explicit impact assessment and current candidate/check identity. Recheck the
changed behavior and affected interactions; preserve evidence for unchanged
surfaces. This does not require another Copilot request. Earlier evidence remains
supporting evidence rather than proof of the new candidate.

Build and test each unit green in its turn. Run required complete integration,
ARM/emulator, device/OLED, storage compatibility, and SRAM checks on the assembled
candidate as applicable to the shipped product. Do not add alpha product variants
merely because historical checklists mention them. Establish exact required
checks from the baseline and selected behaviors before implementation.

## Promotion and later alpha features

Foundation acceptance requires all selected units accepted, complete candidate
checks passing, and no unresolved release blockers. Record the accepted SHA.
Alpha features may be staged earlier in a new manifest using the same unit procedure. Release acceptance remains distinct from internal staging.

Reconstruct the accepted sequence from its recorded base and verify the expected
tree and pins before proposing any future promotion of develop. Preserve the previous develop tip.
Final contents must match the selected manifest, not all of alpha; explicitly
record intentional omissions. Keep dependent fork PRs stacked and unmerged. Future upstream submission
should preserve the independently reviewable units and dependency order.

Rehearsal success does not imply upstream acceptance. Before upstream PRs, verify
the live target base and public dependency availability. Reconcile any difference,
refresh affected evidence, and satisfy upstream dependency/merge requirements.

## Owner correction: unmerged fork stack (2026-09-08)

Fork develop and alpha are agent-controlled staging surfaces. Do not wait for
human approval to author, validate or stack internal PRs. Do not merge into
develop: the foundation targets fork develop and each dependent PR targets its
predecessor branch. Keep the new stack unmerged. A reviewer recommendation for
human review is recorded for upstream/release consideration; it does not block
internal staging. Specific unresolved defects still receive a disposition.

The existing fork develop contains later integrations. Reconstruct the selected
7.14.2 tree on an isolated descendant branch so its PR describes the proposed
foundation replacement without rewriting develop. Record the original target
SHA, exact source tree, intentional omissions and reconstruction checks.
Do not mistake the large replacement diff for a newly authored feature bundle.

## Bound CI work during audit iteration

Batch audit-ledger edits before pushing. After a documentation-only audit push,
inspect active runs for that exact branch and cancel superseded documentation
runs, retaining at most the newest one. Verify cancellation reaches a terminal
state; an accepted cancellation request is not completion. Do not cancel a
release validation run merely because it is slow. Keep exact-head product
evidence distinct from documentation CI. Dispatch combined release validation
once per concrete assembly, recording the run ID and head; inspect that same
run until terminal before deciding whether another run is justified.
