# Firmware rehearsal and acceptance SOP

Owner decision: 2026-09-07. This is the canonical procedure for the new
7.14.2 hardening foundation and subsequent extraction of alpha features.
It supersedes the alpha audit requirement for two whole-tree zero-finding
passes as a prerequisite to staging. Historical rehearsal handoffs are
evidence, not executable instructions or current branch identities.

## Current review policy and authority

Owner correction: 2026-09-24, after Stack 06. Complete a consolidated local
source, compatibility and evidence audit before proposing another paid review.
A green build or repaired last comment does not establish that this preflight
is complete. Copilot is an optional, explicitly authorized external checkpoint
in internal rehearsal; it is required only where the selected upstream/release
contract explicitly says so. Its absence or stale reviewed head does not prevent
local acceptance once the local contract passes. Record the external status
honestly, independently of local acceptance.

The external-checkpoint rules below apply only when that checkpoint is entered.
They do not override local acceptance or authorize an automatic request loop.
One owner authorization permits the stated request, not successive requests
until a clean verdict. Prepare the complete local audit and stable evidence
before proposing a paid request; do not end every repair by asking for another.

## First step: claim the audit block

Before opening an audit worktree, editing code, or requesting review, read the
main firmware worktree's `MASTER-AUDIT-TEMPLATE.md` progress ledger and this
SOP. Select the lowest unclaimed, unaudited **release block** in the recorded
predecessor order. Historical `P` audit units and release stack IDs are distinct.
Check the live PR and predecessor identity, then claim the block in the main
worktree by creating `docs/release/audit-claims/<block-id>/` with plain `mkdir`
(without `-p`). Directory creation must succeed; if it already exists, read
its `OWNER.md` and choose another unclaimed block. Never overwrite a claim.
Immediately write `OWNER.md` with the agent/worktree, UTC time, block ID,
code-bearing PR, and in-progress status, and add the same claim to the master
progress ledger. Other agents must treat a claimed block as unavailable until
its owner records completion or explicitly releases the claim. Claims coordinate
work only; they are not audit or release acceptance.

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
Inventory compile guards on security and release-policy tests at the exact
candidate head. Record which named tests executed in the ordinary full and
Bitcoin-only builds. Any guarded test that is part of the claimed behavior
must also run in an explicit diagnostic build, or the behavior remains
unverified. A failing guarded test blocks a clean local checkpoint until its
root cause and fix are verified; a green ordinary suite cannot override it.

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

## Consolidated local audit before paid review

Use one frozen base/head and a single findings list. Read the complete adjacent
source/test/build/dependency diff, including removed lines. Audit the current
implementation and its callers; a list of changed filenames is insufficient.
Perform these passes locally before declaring review readiness:

| Pass | Required evidence | Failure to resolve before requesting |
| --- | --- | --- |
| Identity and preservation | Accepted immediate predecessor, live PR base/head, dependency pins; disposition for removed guards, declarations, tests, assertions and build registrations | An unexplained deletion or old predecessor, even with green CI |
| Consumer compatibility | Each changed wire bound, field, default, storage policy and API mapped to actual caller behavior; boundary requests through the handler/transport; full/BTC resource effects | A firmware-only check that misses a client's default, such as CoinTable capacity 8 versus a 10-entry request |
| Security and equivalent inputs | Trace input through classifier, specialized handler, fallback, consent, signature/output and cleanup; test missing/zero/padded/nonzero values, length boundaries, split/trailing input and abort/retry as applicable | A guard demonstrated only through its helper or original failing representation |
| Test preservation and execution | Compare predecessor test identities and assertion changes; map newly added and previously guarded tests to actual result files by variant; compare every relevant skip with the unit's claimed scope | A new test never built, an assertion weakened, or an owned behavior hidden behind a later-feature skip |
| Findings, artifacts and status | All inline/body findings dispositioned; check runtime behavior against report wording; stable source/PDF inventory, exact identities and evidence; release-only limitations named | Stale status prose, unsupported claims or a report edit used as a reason for another paid review |

A test-name comparison is a deletion alarm, not proof that assertions are
unchanged; inspect assertion diffs and compile/skip conditions as well. For
skipped owned behavior, run the narrow module with an explicit capability
override or correct its classification. Do not globally enable unrelated
later capabilities. Use independent vectors where practical; preserve a negative
control that fails on the old defect when closure depends on a new assertion.

After batching fixes, audit the remediation delta and adjacent interactions in
a separate pass. Record attempted counterexamples and their outcomes, including
valid neighboring inputs that must continue to work. Stop when no known
in-scope defect or required verification gap remains. A further iteration must
name a concrete defect or gap; do not invent a fixed number of whole-tree passes.

Review readiness needs a short signed-off receipt: reviewer/UTC time, explicit
base/head and pin identities, paths and properties reviewed, finding dispositions,
executed/skipped evidence, counterexamples, open release gates, and the reason
an external review would add value. "Signed-off" identifies the accountable
reviewer; it does not require another person, another agent, or paid service.
Freeze semantic content before formatting the final source/PDF once. Keep live
CI/review outcomes in the PR receipt/ledger with their SHAs so historical prose
does not masquerade as current status or force repeated report commits.

Re-use passing evidence for unchanged code, pins and configuration with an
explicit impact assessment. Documentation-only updates need consistency, render
and diff checks; they do not automatically require another full CI matrix.
New protocol bounds need consumer and resource checks; signing/state changes
need affected positive, negative and continuation checks. Run the full required
matrix once on the final material candidate. Never label carried evidence as a
new exact-head execution.

## Security closure evidence

Owner revision: 2026-09-23, following P02 review #855. Before closing a security
finding, record a contract table with the sensitive value or state, its origin,
observer, build variant, workflow phase, allowed outputs, forbidden outputs and
equivalent representations. Follow the value through bytes, encoded words,
derived values, logs and display pixels. A field disappearing does not establish
that its value is hidden. Resolve contradictions between the documented policy,
implementation and test harness before claiming readiness; do not narrow the
policy merely to make an existing test pass.

Map every changed security-sensitive entry path to an executed assertion. For
workflow deadlines, include each initial and continuation handler, valid progress
near expiry, invalid or empty input, polling, and eventual stalled-session expiry.
For transport changes, exercise the actual main and debug receive callbacks,
including short, complete, no-data and error transfers. Shared-helper tests alone
do not prove callback or handler integration. Record variant-specific exclusions.

After implementation, perform a separate falsification pass: assume the fix is
present and attempt to violate the original contract through another encoding,
a later phase, another callback or a build variant. Use independent expected
values; a harness must not obtain its oracle through an output that the contract
forbids. Cover consent, sensitive display pages, input, result, backup, abort and
restart when auditing a setup ceremony. Use targeted negative controls or
mutations where needed to demonstrate that assertions detect the original defect
and alternate disclosure paths. Record the attempted counterexamples and results.

Inventory both inline comments and review-body observations. Each receives a
stable disposition and evidence, even if the review service created no thread.
An inherited fix requires the same property analysis as a locally authored fix.

Report these states separately: implemented; targeted behavior verified;
integration verified; adversarial contract checks verified; external review
delivered; findings dispositioned; release accepted. Test totals, clean CI,
artifact hashes and predecessor provenance cannot substitute for a property-level
coverage matrix. Name any untested phase or output explicitly. Complete semantic
checks before repeatedly regenerating receipts; retain exact source identities
and refresh evidence when relevant code or dependencies change.

## Copilot only at the late external checkpoint

### Block identity and review coverage gate

Use the release program's block ID, exact predecessor SHA, product head SHA,
and code-bearing PR number as one identity. A historical fix ID such as `P06`
does not mean `release/715-stack-06` and must not be called "Block 6" without
the release stack identity. Before starting a block, compare the live PR's
adjacent diff with the named predecessor and list every changed source, test,
dependency pointer, workflow, and documentation path. If the PR title, report,
or branch name describes a different diff, stop and reconcile the identity.

Classify each PR as **code-bearing** or **receipt-only** from its live adjacent
diff. A receipt-only PR changes documentation/evidence but no implementation,
test, dependency pointer, build, or workflow path. A Copilot review of that PR
can assess the receipt only. It cannot review code already present in the base,
historical commits, or another PR, even if the report quotes those changes.
Never request Copilot on a receipt-only PR to satisfy a firmware block or
code-unit checkpoint. Do not create or retarget a PR merely to manufacture a
reviewable diff. If code review is required, identify the actual code-bearing
PR and exact reviewed base/head; if one does not exist, record the checkpoint
as pending and prepare an appropriately scoped code-bearing review at the
authorized late checkpoint. Preserve prior tests as evidence, not as a
substitute for review coverage.

The preflight must include `git diff --name-status BASE_SHA..FINAL_HEAD_SHA`
and `git diff --numstat BASE_SHA..FINAL_HEAD_SHA`, the live PR base/head, and a
coverage table mapping each declared behavior to the code-bearing diff or an
explicitly labeled inherited-code review. A documentation-only diff is a
hard failure for a firmware-code Copilot checkpoint. Keep separate statuses
for local behavior verification, receipt review, code-review checkpoint,
assembled product, and release acceptance. No single "clean" or "complete"
label may collapse them.
Run `scripts/release/check-code-review-diff.sh BASE_SHA FINAL_HEAD_SHA` as a
minimum machine gate; exit status 2 means no code-bearing path and forbids a
firmware-code review request. A zero exit only proves that some eligible path
changed. The human path-to-behavior coverage table remains mandatory.

### Reviewable audit report before the external checkpoint

All agents use one canonical audit flow: read this SOP and the master form at
`docs/release/MASTER-AUDIT-TEMPLATE.md` in the **main firmware worktree**
(the first entry in `git worktree list --porcelain`) before beginning a block.
Fill the form's
identity, historical Git inventory, current-source reconciliation, findings,
verification, render/preflight, and review-checkpoint sections in the unit's
isolated worktree. Record the master form's commit or SHA256 in the unit receipt.
Do not create an agent-specific substitute flow or treat a copied worktree form
as a different authority. Reconcile any snapshot against the main copy before
the first external review request.

Prepare an audit report for each frozen unit or upstream-shaped batch before
requesting its final review. Give the reviewer both a readable source document
and a PDF generated from that source. The report must identify the exact base,
head, target branch, dependency pins, and included commit IDs. Confirm the live
target still matches the recorded base before presenting the report.
When the report itself is committed in the review PR, record its generation
predecessor in the report and record the resulting final PR head in the PR
description; a file cannot embed the hash of the commit that contains itself.

Before requesting review, freeze the report files in a commit, then generate the
final inventory from an **immutable, explicit base-to-predecessor range** such
as `git diff --numstat BASE_SHA..REPORT_PREDECESSOR_SHA`. Include every PR file,
including the report source and binary PDF (Git shows `-` for binary counts).
Regenerate and commit the report if the first report commit changes the file
list or line counts. Verify the committed final diff with
`git diff --numstat BASE_SHA..FINAL_HEAD_SHA` and compare every path and count
to the report; a report-only correction may use the predecessor range when the
final diff is identical, with the containing head recorded in the PR body.
Do not cite a mutable branch name, `HEAD`, or a one-argument `git diff` as the
reproduction command for a frozen inventory. Confirm that the PDF shows the
same inventory and that its rendered pages are legible.

Include a line-change inventory produced from Git for the PR diff and, when a
small review PR summarizes earlier code units, for each underlying unit commit.
Show additions, deletions, files, and the command/range used. State explicitly
when counts include documentation, tests, submodule pointer lines, or commits
that overlap in their changed lines; do not present a sum of overlapping commit
counts as the net candidate diff. Give every change a short plain-language
description covering the prior behavior, the new behavior, why it matters, and
its regression or validation evidence. Separate direct unit changes from later
interaction changes and from report-only changes.

Map every known in-scope finding to fixed, refuted, accepted limitation, or
pending, with a technical reason and exact evidence. Name skips and unavailable
device checks. Link exact CI run and artifact identities, and explain whether
later commits changed code, tests, pins, workflows, or documentation. A green
earlier run is supporting evidence when the head changes, not an exact-head
pass. Recheck the affected surface and regenerate the report after material
changes. Run a PDF render check and inspect the output before handing it over.

Perform one local preflight before spending a Copilot request: compare the
report table with the final Git diff; check the report and PR body for the exact
base, predecessor, final head, pins, skips, open risks, and review status; open
the PDF; run `git diff --check`; and confirm the PR contains only the intended
files. Apply the block identity and review coverage gate above. Fix all
discrepancies locally and freeze the head before requesting.
Record this preflight in the PR description or audit receipt.

The report supplies review evidence; it cannot guarantee that Copilot or a
human reviewer will return zero findings. Keep delivered-review status and
local readiness as separate statements.

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

At an authorized external checkpoint, request Copilot once only after the
consolidated local audit and code-bearing coverage gate pass. Record the
owner authorization, purpose, immutable base/head, prior request count and
expected value before sending it. If findings arrive, inspect the body and
all inline comments, investigate their shared root causes, and fix related
issues together locally. Repeat the affected audit passes before considering
another request. A changed head makes an earlier review historical; that fact
alone is not a reason to spend another request. Every additional paid request
requires renewed owner direction for that request and a concrete remaining
external-checkpoint purpose. There is no automatic corrective allowance.
Never re-request to test an uninspected report edit, to clear a thread without
a documented disposition, or while an earlier request is still pending. A
timeline request event proves registration; only a delivered current-head
review with body, inline comments, and zero unresolved threads proves a clean
checkpoint. State the number of requests and their outcomes in the receipt.

When a delivered Copilot review on the current final head **and the matching
code-bearing adjacent diff** says `Findings: None`, has zero inline findings,
and leaves zero unresolved threads, mark that code-review checkpoint complete.
For advancement, evaluate the named block's local acceptance contract and
predecessor integration independently; an external clean result alone cannot
satisfy them, and an optional stale external result does not invalidate them.
A generic “Needs a closer look”
overview is not a finding unless it identifies a concrete actionable body-only
issue; quote and disposition any such issue. Do not spend another request to
confirm an already clean result. Keep physical-device and release promotion
gates separate from this audit-unit completion decision.

A required external checkpoint may instead close by explicit owner acceptance
of a technically declined finding after the current-head review, exact-head
validation, complete
inline/body dispositions and zero unresolved threads are recorded. State the
owner exception in the unit receipt and master ledger; never relabel Copilot’s
actual verdict as clean. This does not waive physical-device, predecessor
integration or release-promotion gates.

A failed, missing or quota-limited review is not a clean review. Report Copilot's
actual status separately from internal readiness. Existing substantive findings
must still be resolved or explicitly declined on technical grounds; deferring
Copilot does not waive known defects or any upstream-required review gate.

If an earlier completion claim used a receipt-only Copilot review, correct its
ledger entry. Retain the factual receipt review and test results, mark the
firmware-code review checkpoint **unverified**, and reopen any block completion
that depended on it. Do not spend another Copilot request until the actual
code-bearing scope and authorized checkpoint are ready.

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
