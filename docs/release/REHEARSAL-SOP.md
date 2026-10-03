# Firmware rehearsal and acceptance SOP

Owner decision: 2026-09-07; tiered acceptance revision: 2026-09-21. This is the canonical firmware rehearsal procedure, covering 7.14.x hardening and later alpha extraction.
It replaces the two whole-tree zero-finding prerequisite for staging. Historical handoffs are evidence, not executable instructions or current branch identities.

## Dress rehearsal into fork develop (owner revision 2026-10-03)

This supersedes every earlier statement in this file that a rehearsal does not merge into fork `develop`
(the "Two fork PR types", "Owner correction" and "Final upstream SOP" passages). Fork `develop` is the
rehearsal surface. It starts equal to upstream `develop` and is reset to upstream `develop` when the
rehearsal ends, so merging into it loses nothing. The rehearsal ends with **two fork release branches for
testing** (7.15 and 7.16), and it sends nothing upstream.

The tools are in `docs/release/rehearsal-tools/` (see its README). They assume a clone with a `fork`
remote and, in each of `deps/python-keepkey` and `deps/device-protocol`, a remote named `kk` pointing at
the `keepkey/*` upstream.

### Order of operations (no step is skipped or reordered)

0. **Pin gate first.** Follow `BRANCHING-SOP.md`, "One canonical branch per dependency, never split".
   Before any firmware PR is opened or merged: the two canonical upstream PRs are the only open ones from
   their branches, their heads contain every pin that will be used, and **every block head, the base
   release and `.gitmodules` pass `rehearsal-preflight.sh`**. If the canonical branch lags, bring it up
   first (fast-forward only, owner approval for the upstream push). A rehearsal that starts with split
   pins is invalid and is not repaired by merging on.
1. **CI prerequisites** (below) are in place on the first block.
2. **Base release first.** Upstream's own release PR (7.14.3, `keepkey/keepkey-firmware` #475, head
   `e476580a0`) is merged into fork `develop` as merge #0, ahead of the blocks, because every block is
   built on it. It is the one ref checked with `ALLOW_ANCESTOR=1`.
3. **Blocks one at a time, in dependency order** (`merge-blocks.sh`). For block N: retarget the PR to
   `develop` and reopen it, so a **new** `pull_request` run starts on its merge with the current `develop`
   tip; require that run, and every other run on the head, to be green (only a run cancelled before it,
   which it superseded, is ignored); mark the PR ready if it is a draft; run the pin gate on the head;
   require the previous merge's `push` run on `develop` to be green; merge with a merge commit guarded by
   the head SHA; run the pin gate on the merge commit; record the receipt row. A red or missing run stops
   the rehearsal and nothing merges over it.
4. **Two release branches** from `develop` (`cut-release-branches.sh`):
   `release/7.15.0-rehearsal-<date>` at the merge of the 7.15 tip block and
   `release/7.16.0-rehearsal-<date>` at the merge of the 7.16 tip block. The script refuses unless each
   merge commit's **tree equals the tree of the stack tip CI verified**, so the rehearsal provably
   reproduced the tested code. Names must not collide with existing `release/*` branches.
5. **Full-mode CI.** Unset the rehearsal switch and run CI once on each release branch. Rehearsal runs skip
   the OLED capture and the two evidence jobs, so they prove the merges are green; they are not release
   evidence.
6. **Final validation and receipt.** Pin gate on every merge commit and both release branches; the identity
   table (merge, tree, parents, own diff, pins; `receipt-identity.sh`); the receipt in the owner's handoff.
   Resetting fork `develop` to upstream `develop` is a separate owner action.

### CI prerequisites (each cost a stopped run on 2026-10-02)

* **Rehearsal switch.** The repository variable `KK_CI_REHEARSAL=1` skips the ~8 minute OLED capture and the
  `generate-test-report` and `release-evidence-gate` jobs (a run drops from ~20 to ~7 minutes). The CI gate
  waives exactly those two jobs, and only when they were skipped; any failure or any other skipped job still
  fails it. Set it to `0` for step 5.
* **Fork-only history in the secret scan.** `actions/checkout` with `fetch-depth: 0` fetches every fork ref,
  and gitleaks scans them all, so audit manifests on fork-only branches (commit SHAs and SHA-256 hashes in
  `docs/**/*.json`) raised ten `generic-api-key` findings that upstream's own history does not have. The
  allowlist is an AND of path and pattern; a planted token in `docs/x.json` is still reported. The block CI
  scans only the commits an event introduces, which is why only the base release needed the allowlist.
* **Superseded workflows.** The 7.14.3 release added `release-candidate-audit.yml`, a full copy of the old
  pipeline. It triggers on every pull request and push to `develop`, so once the blocks were retargeted it ran
  7.15/7.16 code through the 7.14.3 pipeline with no capability ledger and failed. The CI block deleted it;
  `ci.yml` is its superset. Check for duplicate workflows when the base release is merged.
* **Stack PRs based on a non-`develop` branch get no `pull_request` CI** (the trigger filters on `master`
  and `develop`), so their only runs were `workflow_dispatch`. The first retarget to `develop` is therefore
  the first real PR run.
* **Waiver authority.** Report waivers are checked against an immutable authority: the base SHA for a pull
  request, the repository variable `KK_ACCEPTED_WAIVER_SHA` for dispatch and push. The first block's PR run
  cannot be judged against a base that has no ledger, which the rehearsal switch avoids by skipping the
  report; the ledger narrows block by block.
* **Concurrency cancels.** Pushing to a PR head starts a run that the next reopen cancels. Wait for a run
  created after the reopen; do not read the PR's check list, which also shows the cancelled leftovers.
* **Draft PRs cannot be merged.** Mark them ready (GraphQL `markPullRequestReadyForReview`, by node id;
  `gh pr ready` and `gh pr edit` hit a Projects-classic error on this repository).

### Traps in the tooling

* zsh does not word-split an unquoted variable, and `$var:refs` is parsed as the `:r` modifier. Use arrays and
  `${var}:`; run loop scripts with `bash`.
* After switching branches, the submodule worktree still sits on the previous branch's pin and shows as a
  modified gitlink. Stage pins with `git update-index --cacheinfo`, never `git commit -a` or `git add -A`.
* Never edit a running bash script in place; bash reads it incrementally.
* Copilot is not requested during a rehearsal (see below).

## Two fork PR types: products and audit units

Owner clarification: 2026-09-08. The main products are fork release branches for 7.14.2, 7.14.3 and 7.15. Small rehearsal branches harden and extract features before accepted changes update those products.
All internal PRs live in the fork. Outside a dress rehearsal, neither PR type is merged into fork develop; the dress rehearsal (above) is the exception.

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
Do not merge or reset develop under this rehearsal authorization (superseded for the dress rehearsal by the first section). Alpha feature staging may proceed on the tested foundation PR before release acceptance; dependent units remain unmerged.
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
it. Owner revision 2026-10-02: autonomous Copilot requests are revoked; ask the
owner, naming the PR, before any request. This supersedes earlier mandatory per-PR clean-Copilot requirements and
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
   operations. Never merge the fork product PR into develop as a prerequisite of an upstream submission. (This concerns upstream, not the fork dress rehearsal.)

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
predecessor branch. Keep the new stack unmerged. (Superseded for the dress rehearsal
by the first section: there the blocks do merge into fork develop, one at a time.) A reviewer recommendation for
human review is recorded for upstream/release consideration; it does not block
internal staging. Specific unresolved defects still receive a disposition.

The existing fork develop contains later integrations. Reconstruct the selected
7.14.2 tree on an isolated descendant branch so its PR describes the proposed
foundation replacement without rewriting develop. Record the original target
SHA, exact source tree, intentional omissions and reconstruction checks.
Do not mistake the large replacement diff for a newly authored feature bundle.
