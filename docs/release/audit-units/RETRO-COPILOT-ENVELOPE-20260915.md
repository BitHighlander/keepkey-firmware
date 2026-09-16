# Retrospective: Copilot review envelope and delayed results

## Outcome

The final-review round did not produce complete Copilot coverage. The 7.14.3
review was refused because its diff exceeded 20,000 changed lines. The 7.15
review examined 167 of 300 files in Lite mode and returned six inline findings
plus one suppressed P1 in the review body. Both results arrived before the
documentation-cleanup force-push, but were discovered afterward.

The CLI was authenticated as the personal `BitHighlander` account. No quota or
billing error was reported. This was an audit-process failure, not evidence of
exhausted Copilot credits.

## Failure sequence

1. We requested reviews on exact squashed heads and observed the timeline
   events.
2. The requested-reviewer lists later became empty while the reviews endpoint
   still appeared empty. We described the jobs as pending without treating
   that transition as a reason to check for delayed delivery before mutation.
3. We cleaned documentation and force-pushed new heads. The reviews had arrived
   shortly before that push.
4. The 7.14.3 response was a line-limit refusal, not a review. The 7.15 response
   was explicitly partial, but still found issues on surfaces our internal
   coverage receipts had called covered.

## Findings and missed audit classes

The Copilot comments remain hypotheses until reproduced or refuted. Regardless
of final disposition, each identifies a missing audit assignment:

| ID | Claim | Missing pre-review check |
| --- | --- | --- |
| C15-01 | OTP entropy failure continues into storage with untrusted bytes | Boot failure consequence traced through the first storage consumer |
| C15-02 | Windows firmware tests link without a `setup()` implementation | Per-platform target and symbol closure |
| C15-03 | Windows `kkemulator` still compiles POSIX UDP code | Per-platform translation-unit and forbidden-import inventory |
| C15-04 | Windows path uses a CMake command newer than the declared minimum | Configure with the documented minimum tool version |
| C15-05 | Storage cleanup observers may recurse through their own macros | Test-probe macro expansion and real-call reachability |
| C15-06 | Zcash crypto executable may not run under the canonical `xunit` command | Test discovery-to-execution-to-report trace |
| C15-07 | Boot signature comparison may consume RNG before RNG initialization | Boot-order transitive dependency review |

The repeated theme is that file assignment was recorded as coverage without a
mechanical end-to-end proof of the claim. Green Linux CI could not close new
Windows support. A compiled test target could not prove execution. Reviewing a
boot function locally could not prove that its callees were safe at that stage
of initialization.

## Corrective gates

The audit SOP now requires:

- a 15,000-line and 120-file operating envelope for each Copilot audit PR;
- independent, disjoint full-context projections whose head tree equals the
  canonical tree, with direct-parent and manifest equality recorded;
- rejection of partial `X/Y`, Lite, or limit-refusal results as clean reviews;
- boot-order, platform-build, minimum-tool, test-execution, and instrumentation
  closure assignments;
- explicit requested, queued, and delivered review states;
- a final review fetch before replacing a requested head; and
- ingestion of suppressed review-body comments and stale-head findings that
  still apply to unchanged code.

## Re-entry criteria

Do not request another Copilot review until all seven claims have individual
dispositions, affected invariants have been re-audited, exact-head CI is green,
and the candidate is represented by bounded audit segments with complete path
coverage. The current green release CI is necessary evidence, but it does not
close these review findings.

## Follow-up: canonical backlog omitted from handoff

The first remediation handoff listed the seven findings from the fork audit PR
but omitted five unresolved threads already present on canonical upstream PR
#476. Three were independent P1s: the tag workflow skipped the Pallas
disassembly gate, storage marker failure forced a destructive reboot path, and
hardware RNG recovery could recurse indefinitely. Work had started waiting for
CI before a direct GraphQL thread inventory exposed them.

This was a provenance failure. A summarized ledger from one PR cannot stand in
for querying every review channel on the canonical PR. The SOP now requires a
direct canonical-plus-audit inventory at discovery, in every re-audit handoff,
and again after a head replacement.

## Follow-up: segmented review removed its own context

The first bounded 7.15 audit used an alphabetical linear stack. Segment 1
contained public headers and top-level CMake changes while their implementations
and target definitions appeared only in later segments. Copilot consequently
reported dozens of missing definitions, conflicting APIs, and undefined targets
that were present in the canonical tree and had already built in full and
Bitcoin-only CI. Those comments were useful as evidence that the projection
was invalid, but they did not provide an efficient audit of the release.

The envelope rule now requires independent full-context projections. Each PR
shows one disjoint manifest against a synthetic parent that already contains
the rest of the canonical candidate. This preserves bounded review size without
hiding cross-file context. A projection must also compile before a review is
requested; tree equality alone is insufficient.

## Follow-up: combined test success hid invalid fixtures

The repair batch passed focused groups, but several new tests depended on
board, timer, FSM, flash, or storage state established elsewhere in the same
process. One malformed multisig test crashed in storage before reaching the
guard it claimed to test. A second review also found that a broad session clear
would have locked ordinary requests even though the stale-stream test passed.

This exposed two prediction errors. We treated aggregate test success as proof
that each regression reached its intended production boundary, and we treated
a focused fix review as sufficient without replaying the broader session-state
matrix. The pre-review packet now requires every global-state fixture to pass
alone in a fresh process, then in shuffled company, with a control that makes
the test fail for the expected reason. It also requires replay of every prior
finding and an explicit residual-risk statement before forecasting a clean
Copilot result.

## Follow-up: confidence was communicated as a promise

Restored Copilot budget was confused with increased confidence in the
candidate, while refusal to guarantee a zero-finding result sounded like low
confidence. Billing only controls whether an external review can run. Candidate
confidence comes from reproducible evidence, and no independent review outcome
can be promised.

The SOP now names four release-audit states and requires an independently
challenged, machine-generated prediction packet. It also adds permanent gates
for isolated global-state fixtures, shuffled interaction runs, dispatch/session
state matrices, fault injection and failing mutations. Future retrospectives
must convert a missed defect class into a test, query or executable gate; prose
alone does not count as process improvement.
