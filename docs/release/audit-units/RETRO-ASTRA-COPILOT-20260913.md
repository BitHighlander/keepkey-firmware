# Audit-round retrospective: Copilot was asked before coverage was complete

The intended outcome was a Copilot review with no unresolved actionable
findings on the corrected release heads. That outcome was not achieved.
Copilot's completed reviews of [7.14.3 #755](https://github.com/BitHighlander/keepkey-firmware/pull/755#pullrequestreview-5193039090)
and [7.15 #756](https://github.com/BitHighlander/keepkey-firmware/pull/756#pullrequestreview-5193037080)
reported findings in both inline comments and their bodies. These are review
claims requiring code triage, not a count of independently verified defects.

## What happened

1. The first Copilot request on each PR returned a quota response, not a
   review. The requester then added billing budget.
2. Only one Astra pilot had run: storage and migration on **#756 only**. It
   found a valid-zero-CRC wipe, an ignored boot-marker write failure, and the
   already-open erase-before-replacement power-loss defect. Its receipt
   explicitly said it was not whole-release coverage.
3. Fresh Copilot reviews were nevertheless requested on **both** PRs. #755
   had no Astra pass at all; #756 still had two new P2s and the deferred P1
   open. No Astra reviewer was assigned to Solana fees, MAYAChain signing,
   display pagination, CI scripts, release receipts, or test quality.
4. Copilot reviewed those other surfaces and reported actionable candidates.
   The 7.14.3 fresh-wallet magic-order bug was in #755; #756 already assigns
   magic before serialization. This was a release-line difference, not a
   storage finding Astra missed on its assigned #756 head.

The storage overlap is evidence that Astra can find some of the same defects:
its zero-CRC and boot-marker findings preceded the corresponding Copilot
comments. It does **not** demonstrate equivalence across the unassigned files.
Nor does the number of Copilot comments prove all are valid; each still needs
reachability, consequence, and regression checks.

## Root cause and correction

The failure was promoting a bounded pilot into a release-wide preflight and
spending a Copilot round despite known open findings. Billing availability was
mistaken for audit readiness. The procedure now requires a file-and-claim
coverage map for each exact release head, including CI, documentation, tests,
and dependency pins, and forbids a final Copilot request while a P1/P2 or
deferred release blocker remains open. An owner-requested early Copilot pass
must be labeled exploratory.

The outcome metric is **zero unresolved actionable findings with complete
coverage and passing release gates**, not a silent model response. A model
that misses a bug is not a release gate; human review and physical-device
testing remain necessary.

## Immediate disposition

- [#762](https://github.com/BitHighlander/keepkey-firmware/pull/762)
  proposes two #755 storage fixes (magic serialization and zero CRC), with
  native emulator regressions and 36 focused passing tests. It does not close
  #755's boot-marker or power-loss findings.
- #756's Solana fee, MAYAChain serialization, pager, and other Copilot claims
  require independent triage. No follow-up Copilot request is warranted until
  a coherent tested batch is on the candidate and the coverage map is complete.
