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

**Coverage gate:** A subsystem pilot is not a whole-candidate audit. Before
calling the Astra round complete, map every changed file to a reviewer and
record a separate pass for tests, CI/release scripts, submodule pins, release
receipts, and claims made in PR descriptions. Review each supported release
line against its own exact base and head; coverage on 7.15 does not transfer to
7.14.3 where their code differs. State any unassigned file or unreviewed claim
as an open gap, even if all assigned reviewers found nothing.

## Fix and verify once per coherent batch

Group related confirmed findings into one scoped patch. Test the affected
behavior on the candidate, run the required release variants, and repeat
the head-specific CI gate. Recheck merge-direction hazards: files touched on
both sides, duplicate definitions, lost guards, changed submodule pins, and
comments that describe code no longer present. Preserve a before/after test
or a concrete manual reproduction for security-sensitive fixes.

One focused Astra verification round reviews the **new diff plus affected
invariants**. It must check that fixes close the original findings without
introducing regressions. Do not restart a full-file audit merely because the
head moved. If findings remain after two Astra rounds, stop the model loop and
assign a human owner or split the candidate. Keep unresolved findings open in
the ledger; do not label the candidate clean.

Before publishing the patch, reconcile the changed-file ledger with the
actual PR diff again. A named reviewer must account for every runtime, test,
CI, script, documentation, and submodule file. If documentation cites an old
head or CI run, label it historical and require a new exact-head receipt.

## Spend a Copilot review only at a stable head

After the Astra ledger has zero unresolved actionable findings and exact-head
CI is green, request **one** Copilot review of the current PR head. First
reply to every existing review item with its fix commit and verification or
specific technical refutation. Resolve only threads whose disposition is
actually complete on the reviewed branch; preserve deferred or blocked threads
as open and list them in the release gate. Record the previous Copilot review
ID. Verify a
new `review_requested` timeline event, then require a newer review whose
`commit_id` equals the frozen head. Read both inline comments and the review
body; a comment with no inline thread is still a finding. Resolve a thread
only after a pushed fix or a documented technical refutation.

Do not start this gate with a known open P1/P2, a deferred release-blocking
finding, or incomplete file/claim coverage. A budget increase or a previous
quota response changes billing availability, not audit readiness. If the
release owner explicitly requests an exploratory Copilot review anyway, label
it exploratory in the ledger and do not interpret it as a final-release round.

If Copilot reports a quota limit, fails to deliver, or reviews an old head,
record **no review**. Do not retry in a loop or consume another request on an
unchanged head. Continue human and hardware gates; request Copilot again only
when service is available and the candidate is stable. A fresh review after
fixes is useful, but cap Copilot at one request per stable head and stop after
three total requests for a candidate. Escalate persistent findings to human
review instead of chasing a green bot response.

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
CI runs (full, bitcoin-only, ARM, native and host):
Astra round 1: assigned subsystems; findings; dispositions:
Astra verification round: changed files; old findings rechecked; new findings:
Copilot: request event; review ID and commit; inline/body findings, or no review:
Human review and physical-device evidence:
Open blockers and release-owner decision:
```
