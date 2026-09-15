# Firmware release audit rounds

Use this procedure for a release candidate or scope-repair PR before asking
Copilot to review it. It replaces repeated Copilot requests as the discovery
loop. An AI review is evidence for reviewers, never release approval.

## Freeze the candidate

Record the repository, PR, actual base branch and SHA, head SHA, submodule SHAs,
changed-file list, and CI run URLs in the release ledger. Compare the PR with
its **actual base**, not an assumed `develop`. A changed head starts a new
candidate; keep earlier findings and their dispositions, but do not call an
older review a review of the new head.

Before an audit round, confirm the diff belongs to the release scope and the
head's build, unit, integration, ARM, and product-variant checks passed. If a
check is unavailable, record that gap. A green check on a different commit
does not count. Pin dependency commits to resolvable upstream or review-branch
heads as described in [BRANCHING-SOP.md](BRANCHING-SOP.md).

After merging a fix PR into an `audit/*` candidate branch, check the workflow
branch filters. If no automatic check runs, dispatch CI on that exact audit
ref with `publish_emulator=false`, record the resulting run ID and its head
SHA, and wait for the aggregate gate. A green run on the fix branch does not
certify the merge commit. Never use a publishing dispatch for audit evidence.

Treat a job rerun as diagnostic evidence only when downstream jobs consume
artifacts from that job. GitHub retains artifacts from the failed attempt, and
a rerun can leave both generations under the same artifact name; a report job
may then download the stale failing JUnit even though the rerun passed. After a
test rerun succeeds, dispatch a fresh exact-head workflow and require its
aggregate gate so every report and artifact comes from one attempt.

## Astra discovery round

If a Copilot review already exists, ingest **all** of its inline comments and
review-body findings before starting another round. Assign each a stable ID in
the ledger, including comments that have no thread. For each item record the
review URL, exact reviewed SHA, affected release lines, owner, severity,
reproduction, disposition, fix commit or refutation evidence, test, and reply
URL. Do not collapse similar comments until each original ID has a traceable
answer. Treat model findings as hypotheses until reproduced or refuted in code.

Use `gpt-6-astra` with high reasoning effort for a **bounded, independent**
review. Divide the changed runtime files by subsystem: storage and migration;
signing and cryptography; transport, protocol and host pins; display and
consent; build, memory and product variants. Give each reviewer one base/head
pair, its assigned files, the relevant release invariants, and a hard output
limit. Do not send the whole repository to every reviewer. Reviewers may read
adjacent code to establish reachability, but must cite the changed line that
introduces or preserves each finding.

Use a fresh Astra context for the pre-Copilot re-audit. The author of a fix
may explain the patch, but must not be its sole reviewer. Give the independent
reviewer the actual base/head SHAs, the full prior finding ledger (including
refutations and deferred findings), and the release invariants. Ask for
counterexamples to the claimed fix and for defects outside the old finding
list. Keep three separate assignments: (1) storage, bootloader and next-boot
fault consequences; (2) signing, protocol and human-visible consent; and
(3) CI provenance, pins, variant coverage and PR/receipt claims. Each report
must distinguish known blockers, newly confirmed defects, and evidence gaps.
The integrator verifies every material claim in source or a reproducible test;
an empty model report does not close an unassigned file or a hardware gate.

Each reviewer returns a compact table with:

| Field | Required evidence |
| --- | --- |
| Finding | Severity, file and line, exact base/head SHA, and trigger |
| Consequence | What is signed, stored, shown, or rejected incorrectly |
| Proof | Reachable path, adversarial input, and why an existing guard fails |
| Disposition | Fix, refute with code evidence, or explicitly defer with owner and release impact |
| Verification | Test or hardware step that would fail before the fix and pass after it |

The integrator deduplicates findings and checks every P1/P2 independently
against the code. Do not use a model vote as proof. A line ledger is coverage
evidence; it is not a substitute for reading the runtime path. Record P3s too,
including a short reason when no code change is warranted.

### Build the invariant matrix before asking for silence

The changed-file ledger answers *where* review occurred. It does not prove the
same security rule was checked at every implementation site. Maintain a second
ledger keyed by invariant, including workflow start/continuation/cancellation;
decoded optional fields that must be consumed or rejected; displayed values
versus signed bytes; setup state after malformed or stale messages; storage
serialization and next-boot consequences; emulator restart isolation; product
variants; and canonical dependency/provenance metadata.

Enumerate every implementation of each invariant with a mechanical search and
record positive and negative cases. One missed sibling reopens the invariant
across every sibling. Fixing only the file named by a reviewer does not close
the finding.

**Coverage gate:** A subsystem pilot is not a whole-candidate audit. Before
calling the Astra round complete, map every changed file to a reviewer and
record a separate pass for tests, CI/release scripts, submodule pins, release
receipts, and claims made in PR descriptions. Review each supported release
line against its own exact base and head; coverage on 7.15 does not transfer to
7.14.3 where their code differs. State any unassigned file or unreviewed claim
as an open gap, even if all assigned reviewers found nothing.

## Internal learning loop: fix, verify, and improve the SOP

Group related confirmed findings into one scoped patch. Test the affected
behavior on the candidate, run the required release variants, and repeat
the head-specific CI gate. Recheck merge-direction hazards: files touched on
both sides, duplicate definitions, lost guards, changed submodule pins, and
comments that describe code no longer present. Preserve a before/after test
or a concrete manual reproduction for security-sensitive fixes.

For storage and boot changes, test the **next boot** as well as the return from
the current call. A commit that reports failure while leaving an invalid boot
marker can still destroy the wallet when the installed bootloader next runs.
Inject both transient and persistent write/readback faults; count a finding
closed only when the failure consequence, not merely the success response, is
resolved. Keep a persistent-fault consequence as a separate open blocker if a
bounded retry only repairs transient faults.

One focused Astra verification round reviews the **new diff plus affected
invariants**. It must check that fixes close the original findings without
introducing regressions. Restart whole-head coverage when a finding exposes a
missing invariant, an unassigned sibling implementation, or an incorrect scope
or dependency assumption.

There is no fixed limit on internal Astra passes before Copilot. An additional
pass is valid only when its assignment differs materially through a new
invariant, counterexample, mutation, release-line comparison, or unreviewed
surface. Repeating the same prompt over the same head is not another audit.

Every pass must leave the audit system stronger. Record at least one reusable
improvement: a new invariant or sibling search, a production-boundary negative
fixture, a mutation proving the test fails without its guard, a cross-release
drift check, or a scope/provenance gate. A clean pass records the new
counterexample class it tested. Do not manufacture prose-only changes; the
improvement must change a future assignment, query, test, or gate.

Do not dismiss a randomized integration failure after one green retry. Repeat
the exact test enough to establish whether it is stochastic, capture the seed
or generated transaction/mnemonic and state transition at the first failure,
and compare it with the candidate base. A retry can establish that the failure
is intermittent; it cannot establish that the product path is correct. Keep
the release gate open until the edge case is fixed, deterministically refuted,
or explicitly classified as inherited test-harness debt with reproducible
evidence and an owner.

After each repair batch, run a focused adversarial pass and a separate
cross-release pass before copying fixes between branches. Compare declarations,
feature availability, dispatch maps and tests, not just similar text. For
security-sensitive guards, locally remove or bypass the intended production
check and require the regression to fail for the expected reason. If mutation
is impractical, record why and trace the production path independently.

Internal convergence requires two consecutive independent Astra gates on the
same frozen head with zero new actionable findings: one invariant/whole-head
gate and one cross-release/evidence gate. Both must explicitly cover tests, CI,
documentation, dependency metadata, and prior review-body findings.

### Required sibling searches learned from release audits

Run these searches as assignments, then inspect every result in context:

| Trigger | Required expansion |
| --- | --- |
| An auto-lock progress hook changes | Enumerate every signing start and continuation handler; require accepted starts and real continuation progress to renew, while polls and incomplete frames do not |
| An auto-lock invariant changes | Enumerate every deadline writer with `rg -n 'reset_idle_time|layoutHomeForced|leave_home|call_leaving_handler|note_workflow_progress' lib`; cross `{AT_HOME, AWAY_FROM_HOME}` with polls, malformed requests, rejected ACKs and accepted progress |
| A handler can block for host or user input | Start an unrelated signing stream first, leave the prompt pending past the deadline, cancel it, then prove a retained ACK cannot resume; enforce this at dispatch with an explicit continuation/poll allowlist so new messages fail closed |
| A continuation is allowed through dispatch | Require both the continuation message type and its matching active engine/setup state; cross every ACK with at least one different live signer and prove the mismatch terminates signing before the handler returns its protocol error |
| A dispatch/session boundary changes | Cross every request class with previously granted PIN/passphrase, AdvancedMode, runtime signer and staged-ceremony state; ending a stale signer must not silently become a full lock, and a new signing request must not coexist with setup |
| A protobuf field becomes decodable | Prove the release consumes and validates it, or explicitly rejects non-empty input; generated bounds alone are not handling |
| A protocol gitlink adds fields or messages | For every release, record its local nanopb bound, dispatch-map entry, handler disposition and negative test; coverage on one release never transfers to its sibling |
| A ticker or human label changes | Compare every confirmation string with every serialized asset/symbol byte and update expected wire vectors separately |
| A cleanup is copied between releases | Compare declaration counts, feature macros, dispatch maps and callers on both heads before applying it |
| A test targets a helper predicate | Add a production-boundary case and mutate/remove the production guard to prove sensitivity |
| A dependency gitlink changes | Verify the live tracking branch contains the pin and update `.gitmodules`, PR provenance, generated reports and candidate documents together |
| A synthetic emulator wakeup changes | Test queued input deterministically and exercise a real stop/start/restart lifecycle |
| An emulator test selects behavior with a compile definition | Trace that definition through every linked translation unit; a target-level define does not recompile a separately linked library, so inspect the final binary for the intended backend symbols and forbidden socket/backend imports |

Before publishing the patch, reconcile the changed-file ledger with the
actual PR diff again. A named reviewer must account for every runtime, test,
CI, script, documentation, and submodule file. If documentation cites an old
head or CI run, label it historical and require a new exact-head receipt.

Prepare a dated re-audit handoff on the same PR or linked documentation PR.
Include the frozen refs, exact-head CI links, prior review IDs and thread
dispositions, test limitations, known blockers, assignment/coverage matrix,
and the next Copilot entry criteria. Update it with independent Astra results
before calling the round complete. If a re-audit finds a new issue, assign an
owner and repeat only the affected patch/invariant verification after a fix.

## Spend a Copilot review only at a stable head

After the Astra ledger has zero unresolved actionable findings, exact-head CI
is green, and the two-pass internal convergence rule is satisfied, request
**one** Copilot review of the current PR head. First
reply to every existing review item with its fix commit and verification or
specific technical refutation. Resolve only threads whose disposition is
actually complete on the reviewed branch; preserve deferred or blocked threads
as open and list them in the release gate. Record the previous Copilot review
ID. Verify a new `review_requested` timeline event, then require a newer review whose
`commit_id` equals the frozen head. Read both inline comments and the review
body; a comment with no inline thread is still a finding. Resolve a thread
only after a pushed fix or a documented technical refutation.

Do not start this gate with a known open P1/P2, a deferred release-blocking
finding, or incomplete file/claim coverage. An inherited finding may be
explicitly deferred by the release owner only after the ledger names the
published baseline, the unchanged failure mechanism, the owner and target
release, and a separate candidate-regression check. Keep its review thread
open and tell Copilot the deferral scope. This exception does not apply to a
new or worsened candidate failure, or waive hardware/coverage gates.
A budget increase or a previous
quota response changes billing availability, not audit readiness. If the
release owner explicitly requests an exploratory Copilot review anyway, label
it exploratory in the ledger and do not interpret it as a final-release round.

If Copilot reports a quota limit, fails to deliver, or reviews an old head,
record **no review**. Do not retry in a loop or consume another request on an
unchanged head. Continue human and hardware gates; request Copilot again only
when service is available and the candidate is stable. A fresh review after
fixes is useful, but cap Copilot at one request per stable head and stop after
three total requests for a candidate. Any Copilot finding reopens the internal
invariant loop; do not immediately ask Copilot to review its repair. Add the
missed rule to the matrix, iterate materially distinct Astra passes, and obtain
two clean internal gates on the final head before spending another request.
Escalate persistent findings to human review instead of chasing a green bot
response.

Use one deliberate status check after the review request, then wait for a
notification or a reasonable interval before checking again. Polling more
often does not accelerate the review and obscures the candidate's review ID
and head identity.

## Release decision

The release ledger must link the frozen head, CI results, Astra findings and
dispositions, Copilot result or explicit absence, dependency pins, and human
review. Physical-device signing, screen reading, setup/recovery, storage
migration, RNG, and full/bitcoin-only product-boundary tests remain separate
gates. A virtual emulator signature does not satisfy a physical-device gate.
No `develop` merge, tag, signing, publication, or release follows from model
output alone; the release owner closes those gates against the same head.

### Ledger entry template

```text
PR / actual base SHA / candidate head SHA:
Dependency pins and changed-file ledger:
Invariant matrix and mechanical sibling searches:
CI runs (full, bitcoin-only, ARM, native and host):
Astra rounds: distinct assignment/counterexample; findings; dispositions:
SOP/test/query improvement contributed by each round:
Two-pass convergence: invariant/whole-head gate; cross-release/evidence gate:
Copilot: request event; review ID and commit; inline/body findings, or no review:
Human review and physical-device evidence:
Open blockers and release-owner decision:
```
