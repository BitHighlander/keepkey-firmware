# Firmware release audit rounds

Use this procedure for a release candidate or scope-repair PR before asking
Copilot to review it. It replaces repeated Copilot requests as the discovery
loop. An AI review is evidence for reviewers, never release approval.

## Freeze the candidate

Complete the topology gate in [BRANCHING-SOP.md](BRANCHING-SOP.md) first. Do
not begin the discovery loop on a fork-only audit branch and merge `develop`
afterward. The canonical upstream PR must already target `develop`, its live
head owner and OID must match the candidate, and fork `develop` must equal
upstream `develop`. Any later base merge or conflict resolution creates a new
candidate that must pass changed-file reconciliation, exact-head CI, and review
again.

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

Query review threads and review bodies directly on the **canonical upstream
release PR** and every fork audit PR. Do not use a handoff summary as the
backlog source. Record the canonical PR's unresolved-thread count and latest
review ID in the handoff, then repeat the query after each head replacement;
an audit PR can be clean while the upstream PR still holds actionable findings.

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

### Make the harness prove test independence

Any test that touches board, timer, flash, storage, FSM, transport, wallet,
PIN/passphrase, signer, or confirmation state must own that state explicitly.
Use shared setup and teardown helpers that initialize each required subsystem,
restore replaced flash, clear storage and wallet state, abort live workflows,
and restore callbacks. Do not depend on test order or state left by another
fixture. Guard one-per-process initialization such as board and timer startup;
reinitializing intrusive global lists is a harness defect.

For every new or changed global-state regression:

1. run it alone in a fresh process;
2. prove it reaches the intended production boundary rather than an earlier
   setup, decoding, storage, or authorization failure;
3. run it with its neighboring suites in at least three recorded shuffled
   orders; and
4. retain a control that removes or reverses the production guard and makes the
   test fail for the expected assertion.

CI must run the isolated and shuffled gates for security-sensitive fixtures.
A combined-suite pass cannot replace either gate.

### Audit protocol state transitions as a matrix

Handler-level coverage is insufficient when dispatch, session, or auto-lock
code changes. Build a table-driven matrix whose rows are existing states and
whose columns are incoming message classes. Include at least:

- locked and unlocked wallets with PIN and passphrase caches;
- each active streaming signer and every continuation, poll, unrelated start,
  cancellation, timeout, malformed frame, and stale ACK class;
- AdvancedMode, runtime ClearSign metadata, and staged setup ceremonies; and
- home, confirmation, screensaver, and expired auto-lock states.

For each cell record whether the message is accepted, rejected, terminates the
old workflow, renews the idle deadline, clears credentials, or changes visible
state. Tests must assert the permitted side effects as well as the response.
Generate the matrix from the dispatch map where possible so a newly registered
message cannot silently escape coverage.

### Use faults and mutations as closure evidence

Exercise security boundaries with malformed protobufs, absent optional fields,
maximum-length fields, short buffers, stale continuations, interrupted writes,
readback mismatches, and transient and persistent hardware failures. Trace the
bytes displayed, serialized, signed, stored, and consumed after reboot.

For each security-sensitive fix, prefer a small mutation that deletes, bypasses,
or inverts the guard. The regression must then fail at the intended assertion.
Record the mutation and failure in the audit receipt; never commit the mutated
production code. When mutation is impractical, record the reason and provide an
independent production-path trace.

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
| A continuation is allowed through dispatch | Require both the continuation message type and its matching active engine/setup state; cross every ACK with inactive state and at least one different live signer. Rejection must terminate stale signing, preserve unrelated setup state, and send a terminal wire response so the host cannot wait until timeout |
| A dispatch/session boundary changes | Cross every request class with previously granted PIN/passphrase, AdvancedMode, runtime signer and staged-ceremony state; ending a stale signer must not silently become a full lock, and a new signing request must not coexist with setup |
| A protobuf field becomes decodable | Prove the release consumes and validates it, or explicitly rejects non-empty input; generated bounds alone are not handling |
| A variable-length field is displayed before serialization | Test the generated protocol maximum through the complete serializer and independently reconstruct the signed bytes; trace whether each scratch buffer contains the field or the field is streamed directly, rather than inferring capacity from a nearby declaration or sibling implementation |
| A protocol gitlink adds fields or messages | For every release, record its local nanopb bound, dispatch-map entry, handler disposition and negative test; coverage on one release never transfers to its sibling |
| A ticker or human label changes | Compare every confirmation string with every serialized asset/symbol byte and update expected wire vectors separately |
| A cleanup is copied between releases | Compare declaration counts, feature macros, dispatch maps and callers on both heads before applying it |
| A test targets a helper predicate | Add a production-boundary case and mutate/remove the production guard to prove sensitivity |
| A handler borrows shared confidential scratch | Enumerate every exit after acquisition and use the scratch owner's public scrub API; reject const-casts or alias-based clearing that duplicate ownership knowledge in callers |
| A public protocol integer is narrowed | Range-check in the original protocol width before any cast; add a value such as 256 that aliases a valid narrow slot after truncation |
| A runtime trust decision is displayed | Repeat the trust tier at the final signing screen; a warning shown only when metadata is loaded is not signing-time consent |
| A clear-sign decoder accepts dynamic calldata | Parse and display every execution-affecting tail element, or route the whole request to raw-calldata review |
| A decoder argument index is repaired | Write the complete ABI word map beside the fix and audit every sibling overload. Compile success cannot detect a valid pointer to the wrong 32-byte word; reject any index greater than or equal to the matched arity |
| A candidate adds a user-visible failure string | Apply the repository's translation/localization convention at the introduction site, including strings embedded in guard macros |
| A dependency gitlink changes | Verify the live tracking branch contains the pin and update `.gitmodules`, PR provenance, generated reports and candidate documents together |
| A synthetic emulator wakeup changes | Test queued input deterministically and exercise stop/start plus shutdown/init in one loaded library. Rebuild intrusive timer, animation and transport queues from their backing arrays; re-pushing nodes onto retained lists can create cycles or preserve callbacks from the prior wallet |
| An emulator test selects behavior with a compile definition | Trace that definition through every linked translation unit; a target-level define does not recompile a separately linked library, so inspect the final binary for the intended backend symbols and forbidden socket/backend imports |

Run the repository's exact static-analysis command locally after the final
preprocessor and control-flow edit. A compiler build is not a substitute:
cppcheck evaluates alternate macro configurations and can expose unreachable
branches that the selected build removes. Record the command and exit status
in the prediction packet.

Before publishing the patch, reconcile the changed-file ledger with the
actual PR diff again. A named reviewer must account for every runtime, test,
CI, script, documentation, and submodule file. If documentation cites an old
head or CI run, label it historical and require a new exact-head receipt.

Prepare a dated re-audit handoff on the same PR or linked documentation PR.
Include the frozen refs, exact-head CI links, prior review IDs and thread
dispositions from both the canonical and audit PRs, their independently queried
unresolved-thread counts, test limitations, known blockers,
assignment/coverage matrix, and the next Copilot entry criteria. Update it with independent Astra results
before calling the round complete. If a re-audit finds a new issue, assign an
owner and repeat only the affected patch/invariant verification after a fix.

## Spend a Copilot review only at a stable head

### Produce a review-prediction packet

Do not predict a clean external review from a green aggregate alone. Before
spending the request, publish one compact packet that another reviewer can
reproduce:

- replay every prior inline and review-body finding against the frozen head,
  with a fix, code-backed refutation, or explicit release-owner deferral;
- run every changed test that touches process-global board, timer, FSM, flash,
  storage, transport, or signer state alone in a fresh test process;
- inspect direct board/timer/FSM initialization in tests and use the shared
  bootstrap where repeated initialization can corrupt global state;
- run the affected fixtures together in shuffled order after the isolated
  runs, and preserve a failing mutation for each security guard where
  practical;
- record exact-head CI, canonical and audit-PR unresolved-thread counts, audit
  projection tree/parent/manifest equalities, and the full-context build result;
  and
- state the remaining uncertainty. A reviewer may forecast zero findings only
  when that list contains no known actionable defect or unverified claimed
  closure.

If an isolated test fails after passing in a suite, treat the fixture as
invalid until its own setup is complete. A crash before the intended guard,
an assertion on unrelated storage state, or success caused by a preceding test
is not evidence for the production invariant.

Generate this packet with a repository script rather than assembling it from
memory. The script must exit nonzero when any required datum is absent or
inconsistent. Its machine-readable receipt must contain:

- repository, actual base and candidate head SHAs, dependency gitlinks and
  candidate tree hash;
- canonical CI run IDs and conclusions for every required product variant;
- canonical and audit-PR review IDs and unresolved-thread counts;
- every prior finding ID, reviewed SHA, disposition and verification evidence;
- changed-file-to-invariant, test, variant and reviewer assignments;
- isolated, shuffled, fault-injection and mutation results; and
- projection direct-parent, tree, manifest-union and duplicate-path checks.

The human-facing packet should summarize only failures, gaps, residual risk and
links to that receipt. Generated evidence is immutable for its head SHA. A head
change invalidates the packet and requires regeneration.

Validate the receipt from a checkout containing the candidate and projection
objects:

```sh
python3 tools/release_audit_preflight.py \
  --verify-github \
  docs/release/audit-units/<candidate>-prediction.json
```

The validator re-queries the canonical PR head and base, CI checks and review
threads from GitHub, then checks the candidate tree and diff,
finding dispositions, changed-file assignments, required test-evidence kinds,
thread counts, projection parents and trees, manifest equality and union, and
explicit residual risks. Its successful JSON output is the packet's readiness
result; handwritten claims cannot override a failure.

### Review the prediction, not the desired outcome

Before requesting Copilot, a reviewer who did not author the last repair batch
must try to falsify the packet. They sample finding dispositions, rerun at least
one isolated fixture and mutation, inspect one state-matrix row end to end, and
verify one projection mechanically. Record discrepancies as findings.

Use confidence language precisely:

- **blocked:** a known release defect or required gate is open;
- **incomplete:** no known defect, but required evidence is missing;
- **ready for external challenge:** all required evidence is present, no known
  actionable defect remains, and residual uncertainty is listed; and
- **externally clean:** a new complete exact-head review has no actionable
  inline or body-only finding and no unresolved thread.

Payment, quota availability, elapsed time, or a prior partial review never
changes these states.

### Preflight the review envelope

Measure the live PR before requesting Copilot. Record additions, deletions,
changed files, and the exact base/head pair. Copilot's hard refusal threshold
is 20,000 changed lines; use 15,000 lines and 120 files as the operating limit
so generated statistics and late cleanup do not cross the service boundary.
Documentation cleanup does not make an oversized runtime review complete.

When a candidate exceeds either operating limit, create independent,
full-context audit projections with disjoint diffs. For each segment, build an
audit base whose tree equals the complete canonical candidate except that the
segment's manifest paths are restored to the canonical base. Its child audit
head restores those paths to the candidate. The PR therefore shows only the
bounded segment while every header, implementation, build target, and test
outside that segment is already present for analysis and compilation. Do not
use an alphabetical linear stack: early segments omit later counterparts and
turn dependency-order artifacts into false API and build findings.

Each audit PR stays under both limits and carries a machine-generated path
manifest. The union of the manifests must equal the canonical base-to-head
diff with no missing or repeated path. Every audit head tree must equal the
canonical candidate tree; every audit base-to-head diff must equal its manifest
and the base must be the audit head's direct parent. Review every segment; a
review of one projection is not a whole-candidate review. Record all tree and
manifest equalities explicitly. Keep the canonical release PR as one concise
release commit.

Copilot's result must state that it reviewed the full segment. A response that
reports `Files reviewed: X/Y` with `X < Y`, Lite coverage, a line-limit refusal,
or any other truncation is incomplete coverage even when it contains useful
findings. Ingest its findings, but do not record a clean review.

Before spending the request, run these mechanical assignments in addition to
the subsystem review:

- **Boot-order closure:** enumerate every new boot-path call and all services it
  transitively uses before entropy collection, DRBG initialization, storage
  initialization, and display/USB setup. Inject each failure and trace whether
  boot, storage, or signature verification consumes untrusted state afterward.
- **Platform build closure:** for each newly claimed platform, configure and
  link every target enabled by that platform with the documented minimum CMake
  version and compiler. Enumerate every compiled translation unit and reject
  forbidden platform headers, symbols, and libraries in the final binaries.
- **Test execution closure:** prove that each new test executable is invoked by
  the command CI actually runs and appears by name in the resulting JUnit or
  CTest inventory. Compiling or registering a target is not execution evidence.
- **Instrumentation closure:** inspect macro interposition, wrappers, and test
  probes for recursion or self-calls. Run the probe through the observed real
  implementation and use a failing control or sanitizer where practical.

These checks are release-line specific. A Linux emulator build does not prove
Windows support, and a release-audit side job does not prove that `make xunit`
or the canonical aggregate report includes a test.

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

After requesting review, record three distinct states: requested, queued, and
delivered. A `review_requested` event proves only the first. An empty requested
reviewer list is not proof of failure or completion; immediately inspect the
reviews endpoint and timeline before interpreting it. Before force-pushing or
replacing a requested head, perform one final review fetch. Ingest any delayed
review of the old head and apply every finding whose code is unchanged on the
new head. Review-body `Suppressed comments` are findings and receive stable
ledger IDs exactly like inline comments.

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
