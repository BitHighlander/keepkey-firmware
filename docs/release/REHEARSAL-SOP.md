# Firmware rehearsal and acceptance SOP

Owner decision: 2026-09-07; tiered acceptance revision: 2026-09-21. This is the canonical firmware rehearsal procedure, covering 7.14.x hardening and later alpha extraction.
It replaces the two whole-tree zero-finding prerequisite for staging. Historical handoffs are evidence, not executable instructions or current branch identities.

## Two fork PR types: products and audit units

Owner clarification: 2026-09-08. The main products are fork release branches for 7.14.2, 7.14.3 and 7.15. Small rehearsal branches harden and extract features before accepted changes update those products.
All internal PRs live in the fork. Neither PR type is merged into fork develop.

| PR type | Head and target | Purpose and acceptance |
| --- | --- | --- |
| Release product | Main fork release branch → fork `develop` | Cumulative, buildable product candidate with a release manifest, exact pins, accepted-unit receipts and complete product checks. Its large diff is an integration view, not a request to rediscover every issue on every iteration. |
| Audit unit | Isolated rehearsal branch → fork `develop` when independent; otherwise → its immediate predecessor | One bounded behavior or defect, reviewed and tested locally against its recorded base. Dependent units stay stacked and unmerged into develop. |

Both types belong to fork-develop staging. A dependent audit PR targets its predecessor to keep the review diff small; do not retarget every stack member to develop.
The existing F00–F05 stack is rehearsal evidence, not the complete 7.15 product.

## Tiered, sequential acceptance

Release work advances one adjacent-PR review block at a time, with one written contract, predecessor and receipt. Block N+1 may be inventoried but not implemented, restacked, published or sent to hosted CI until N is accepted.
A passing cumulative tree cannot waive a failing or unverified lower block.

Every block moves through exactly these states:

`DEFINED -> MUTABLE -> LOCAL-QUALIFIED -> FROZEN -> PUBLISHED -> HOSTED-QUALIFIED -> ACCEPTED`

- `DEFINED`: owner, predecessor, scope, exclusions, invariants, capability
  profiles and checks are recorded. No implementation claim exists.
- `MUTABLE`: implementation and focused review are in progress. Evidence from
  an earlier head is historical only.
- `LOCAL-QUALIFIED`: the exact head passes its required local Docker contract.
- `FROZEN`: head, tree, predecessor, submodule pins and receipt are immutable.
- `PUBLISHED`: the frozen identities, branch and PR agree with the receipt.
- `HOSTED-QUALIFIED`: the required GitHub checks passed once on that exact head.
- `ACCEPTED`: there are zero unresolved block-owned findings and all evidence is
  attached. Only this state permits work to advance to the next block.

There is no partial acceptance and no informal state such as "looks green",
"mostly done" or "converged". If a frozen block changes, move it back according
to the invalidation table below. If an accepted lower block changes, invalidate
it and every dependent block before proceeding.

### Measured definition of done for one block

A block is `ACCEPTED` only when every item below is true:

1. **Scope:** exactly one independently explainable behavior or foundation slice;
   all observed changes are either owned by the block or explicitly inherited.
2. **Size:** fewer than 20,000 changed lines in the GitHub adjacent PR diff.
   Aim for at most 5,000 manually authored changed lines. Generated or imported
   material above that target needs its own provenance record and review method.
3. **Identity:** exact base SHA, head SHA, tree SHA, submodule SHAs and capability
   profile are recorded; the head is a direct descendant of its declared base.
4. **Review:** zero unresolved critical, high, release-blocking or block-owned
   findings. Every finding has a stable ID, affected head, owner, severity,
   disposition and verification evidence. A reviewer reply or green check does
   not close a substantive finding without a technical reproduction or rationale.
5. **Local checks:** formatting, static analysis and focused regression tests pass;
   every distinct capability profile introduced or inherited by the block passes
   in the pinned Docker environment. Actual passes, failures and skips are recorded.
6. **Isolation:** tests that modify environment variables, global state, transport,
   emulator state or storage restore them with fixtures. A changed test harness
   passes its isolation regression in both normal and altered suite order.
7. **Repeatability:** the focused failing-before/passing-after regression is
   demonstrated, and local qualification succeeds from a clean checkout with
   direct pins and every nested submodule consumed by active build/test paths
   initialized. Identify excluded nested vendor/test trees in the receipt;
   their parent gitlink remains pinned, but an unbounded deep clone is not a gate.
   A flaky or unreproduced pass is not a pass.
8. **Publication:** the PR base/head, adjacent diff and description match the frozen
   receipt. Required hosted checks pass once on that exact head with no unexplained
   skipped, cancelled or neutralized gate.
9. **Failure paths:** for each owned security invariant, record the success path,
   failure/abort branches and their distinguishing negative tests. Fault-inject
   irreversible writes, entropy failures and signing/display failures where a
   normal green suite cannot reach them. An untested branch is an evidence gap,
   not an assumed pass; record why a test is infeasible and the alternate review.

Use this scorecard in every block receipt. A block with any exceeded limit is not
done, regardless of its review history or the state of later blocks.

| Measure | Acceptance limit |
| --- | ---: |
| Unresolved critical/high/release-blocking findings | 0 |
| Unresolved block-owned findings | 0 |
| Unexplained test failures | 0 |
| Unreviewed or unexplained required-test skips | 0 |
| Flaky retries counted as passing evidence | 0 |
| Stale, moving or unreachable dependency pins | 0 |
| Adjacent changed lines | < 20,000 |
| Manually authored changed lines without an explicit exception | <= 5,000 target |
| Distinct declared capability profiles lacking local Docker evidence | 0 |
| Active hosted runs for the PR/head | <= 1 |

Record counts, not only a `pass` label. Required skips may exist only when each
has a stable identifier, technical rationale and owning future release or human
gate; an expected skip is reviewed evidence, while an unexplained skip exceeds
the limit above.

Keep a subsystem coverage ledger for foundation or cross-cutting blocks. Name
each changed runtime, test-harness, build, workflow and dependency surface;
assign an owner/reviewer and link its focused tests and failure-path review.
The line-count limit is a publication constraint, not a measure of review
completeness. If the ledger is too broad to review coherently, split the block
before freezing it.

The iteration limit is evidence-based rather than calendar-based. Each review
cycle must close a named finding or add named missing evidence. After three
consecutive cycles expose the same root cause, stop iterating on that shape:
split the block, reduce its contract or fix the shared harness before continuing.
After two consecutive failures caused only by CI infrastructure, stop rerunning
GitHub and reproduce or repair the problem locally. These limits prevent churn;
they never convert a failure into acceptance.

### Release-level tiers

The complete release progresses through these tiers only after every constituent
block is `ACCEPTED`:

1. **Block acceptance:** accept PR 1, then PR 2, in dependency order.
2. **Product integration:** reconstruct the accepted sequence and verify the exact
   final tree, companion pins, exclusions and capability-profile inventory.
3. **Local product qualification:** run regular and bitcoin-only Docker builds,
   native tests, canonical integration, strict OLED evidence, storage/power-cycle
   coverage and ARM/resource checks required by the manifest.
4. **Publication qualification:** publish the immutable sequence once and run the
   protected hosted checks once per exact head.
5. **Human-audit ready:** generate the audit handoff from the frozen manifest.
   Hardware testing, merging and release publication still require authorization.

Do not reopen accepted blocks for optional cleanup. New evidence that affects an
accepted invariant reopens the owning block; unrelated improvements go to a later
release backlog.

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

Owner revision: 2026-09-08; authorization clarification: 2026-09-21. Continue
using Codex for implementation and local review. Copilot is not an internal
staging acceptance gate and remains off unless the owner explicitly authorizes
it. This supersedes earlier mandatory per-PR clean-Copilot requirements and
review-round ceiling blockers.

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

A review pass is not evidence of correctness. Do not weaken tests, remove required coverage or redefine behavior merely to obtain a clean result.
Confirmed release-critical defects still block release. Optional style preferences
and unrelated improvements go to a separate backlog rather than reopening a
passing candidate. A recurring finding requires root-cause analysis or a smaller
unit, not additional unchanged review prompts.

## Pre-push gate, self-review classes and agent handoff

Owner request: 2026-09-25, after the 00b retrospective
(`audit-units/715-00b-retro-20260925.md`). The rules above were already
correct in principle; 00b broke them in sequencing and enforcement. These
rules are mechanical so they do not depend on memory.

**Pre-push gate.** Run `scripts/preflight.sh` after the last edit and
immediately before every push. It mirrors CI Stage-1 (a red Stage-1 job skips
the whole build graph) and fails closed. Do not push on a failure, with one
recorded exception: if only the Docker-backed step failed because Docker is
unavailable, push and state in the PR that hosted CI is the only
static-analysis evidence for that head. Do not
treat a local tool that differs from CI's version as a substitute. Local
qualification runs pinned, clean submodules only; a dirty submodule is a
different product.

**Negative controls.** A new check, script, poll or gate counts as evidence
only after it has been shown to fail on a known-bad input. A silent tool is
not a passing tool until its control has fired. This applies to agent
scripts: API polls must paginate, and batch writes must be verified by
reading the result back.

**Self-review classes.** Before any external review, walk the block's own
diff for these recurring classes and fix or disposition each hit:

| Class | Question to answer in the diff |
| --- | --- |
| Invariant in a comment | Which comment states a fact? What code, `_Static_assert` or test proves it? |
| Consent order | Is every value validated before it is displayed, and displayed before it is hashed or signed? |
| Buffer bounds | Is every bound computed by subtraction from the end, never by forming a pointer past it? |
| Configuration duplication | Does any option, pin or ledger entry now appear twice? |
| Gate trust | Does any gate read free text from an artifact instead of a checked-in ledger or an exact identity? |
| Dead guards | Did a new early return make a later check unreachable? |

**Local runtime health.** Before starting a long local job, check
`docker info` with a timeout, and run images for the host architecture.
Give every background job a time limit. If a job makes no progress for
10 minutes, stop it and report. If Docker is unavailable, qualify on hosted
CI and say so explicitly (owner direction, 2026-09-24).

**Agent handoff record.** Work handed from one agent to another must be
committed, as a WIP commit if needed, never left as an uncommitted tree. It
must carry a short note listing: head SHA, dirty or unpinned dependencies,
the checks that ran and the exact tree each ran against, open findings, and
the next step. A pasted transcript is not a handoff record.

## Copilot only with explicit owner authorization

Do not request Copilot during authoring, local hardening, predecessor propagation,
or routine fork PR staging. Do not create a PR or push solely to trigger Copilot.
Quota exhaustion, missing delivery or a historical round ceiling does not block
internal work or acceptance under the local contract above.

Copilot is not an implicit release or upstream gate. Request it only when the
owner explicitly authorizes it for identified frozen, upstream-shaped PRs. An
instruction to complete, audit, publish or prepare the release is not Copilot
authorization. If authorized, enter the checkpoint only after the release and
its proposed upstream units pass internal acceptance. Audit the small final units
and their affected interactions; do not substitute a broad product diff for them.
Never start an unbounded repeat-until-silent Copilot loop. The bounded loop in
"Review budget and block splitting" below is the standing authorization for
re-requests. Preserve prior dispositions and review counts.

A failed, missing or quota-limited review is not a clean review. Report Copilot's
actual status separately from internal readiness. Existing substantive findings
must still be resolved or explicitly declined on technical grounds; deferring
Copilot does not waive known defects or any upstream-required review gate.

## Review budget and block splitting

Owner decision: 2026-09-25, after the 00b retrospective. This is the
standing authorization for Copilot on frozen blocks; no per-round approval
is needed.

1. **Budget.** Each frozen block gets up to **3 Copilot rounds**, requested
   by the agent without asking. Use Balanced effort where it is available.
2. **Each round.** Fix every actionable finding and audit its class across
   the block. Reply to and resolve every thread. Then run
   `scripts/preflight.sh` and get hosted CI green on the new head. Only then
   request the next round.
3. **Pass.** A round passes when a delivered review on the current head has
   no finding that needs a code change. A decline needs technical evidence
   on the thread. A finding the agent would decline on a security-relevant
   path goes to the owner instead of being declined.
4. **Failure.** A round with any finding that needs a code change is a
   failure. A quota failure, or a review that never arrives, is neither a
   pass nor a failure; it does not use up the budget.
5. **Split after 3 failures.** Re-cut the block into smaller consecutive
   blocks, using the next unused IDs in sequence (for example, 00b becomes
   00b, 00c and 00d). Each piece holds one bounded behavior or subsystem, is
   stacked in dependency order, and gets a fresh 3-round budget. Repeat for
   any piece that fails 3 rounds, until the entire block is approved. The
   agent plans and performs the split without asking. It records the split
   in a receipt that maps every file, finding and disposition from the
   parent to exactly one piece, so no fix or evidence is lost. Splitting
   never waives an open finding.
6. **00b transition.** 00b's seven earlier rounds do not count. The owner
   authorized 3 more rounds on 00b before any split (2026-09-25).

## Final upstream SOP

1. Select an accepted release receipt and pin the live upstream target. Prepare
   the final small PR sequence on fork branches, recording source units and public
   dependency availability. Account for every intended product change or explicitly
   record what is deferred from this upstream batch.
2. Reconcile upstream-base differences locally and rerun affected checks plus the
   required assembled-candidate checks. Freeze the exact proposed heads and bases.
3. If explicitly authorized, perform the requested Copilot audits on the frozen
   fork PRs. Batch actionable findings into local fixes and revalidate. Record
   review IDs, head SHAs and technical dispositions. A quota failure is pending,
   not clean; never represent it as a delivered review. Without authorization,
   record `not requested` and proceed through the declared human-review gates.
4. Record the final audit outcome honestly. For an authorized external review,
   the target is a delivered review with no actionable findings on the final
   candidate; any declined finding retains its rationale and must not be reported
   as a literal “no findings found” response. Material changes after review require
   an impact assessment and refreshed audit coverage before that checkpoint is
   considered complete.
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

Use this minimum invalidation matrix instead of an ad hoc judgment:

| Change after evidence | Evidence that must be refreshed |
| --- | --- |
| Documentation only | Document consistency and manifest-reference validation |
| Workflow only | Workflow syntax, trigger/concurrency behavior and hosted gate |
| Test or harness | Affected tests, isolation/order regression and capability profiles |
| Firmware runtime | Affected focused tests, all affected Docker profiles and downstream block identities |
| Companion runtime/test | Companion tests and every consuming firmware capability profile |
| Submodule/gitlink | Pin/provenance checks and affected clean dependency-graph builds/integration |
| Restack, reorder or new base | Ancestry, adjacent diffs, line counts, receipts and every dependent head |
| Security policy/invariant | Owning security review, mutation regressions and affected product qualification |

A handoff document never validates itself or claims its own future SHA. Attach
the frozen head/tree and hosted run in a post-push PR comment or external
machine-readable manifest; verify checked-in receipts against that attachment.
An acceptance comment is head-specific: it must name the exact head and hosted
run. A changed head or new substantive finding immediately reopens the block
and dependent blocks, even if old comments still say `ACCEPTED`. Post a new
status on the PR rather than silently relying on an earlier acceptance record.

## Docker-first and hosted-CI budget

GitHub is the immutable-head confirmation environment, not the debugging loop.
Before pushing a block, run focused checks and capability profiles in pinned Docker, using CI's exact entrypoint and pre-suite phases; direct test commands are diagnostic only. Before publishing the assembled product, complete product qualification locally.

- Run lightweight format, static, secret, topology and pin checks on every slice.
- Run expensive full-product integration on the final product and only on earlier
  blocks whose capability profile or owned behavior requires it.
- Allow at most one active hosted run per PR and exact head. Cancel superseded runs.
- Configure workflow concurrency by workflow and PR, with older runs cancelled.
- Do not manually rerun an unchanged failure. First identify a concrete flaky or
  infrastructure cause, or make and locally validate a relevant change. For a
  red hosted test, retain its exact assertion/response and head, rerun focused
  and full-suite locally, assert each request/response boundary (including
  intermediate acks), inspect suite order, and keep the finding open until a
  cause and distinguishing regression are named.
  A passing local replay or subsequent hosted retry never erases the red run.
- Two infrastructure-only failures end hosted retries until the failure is locally
  reproduced, the workflow is repaired, or the provider recovers.
- Skipped, cancelled, timed-out and missing jobs are not successful evidence.

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
