# Complete release audit coverage

Status: pending review. This inventory is scope evidence, not completed audit evidence.

Frozen fork develop: `da075b8cb717b56dc1023edb52c2ccdf171b8a08`. Release-product PRs #650, #627 and #629 remain unmerged.

The JSON ledgers record every PR path without rename collapsing, its phase, review
status and evidence references. Changed shared files require per-product comparison;
equal filenames do not establish equal implementations. Deleted code must receive
an explicit product-scope and consumer disposition. Dependencies require review of
the pinned dependency delta, not merely confirmation that a gitlink exists.

| Phase | 7.14.2 paths | 7.14.3 paths | 7.15 paths | Status |
| --- | ---: | ---: | ---: | --- |
| P00-scope-documents | 106 | 25 | 51 | Pending |
| P01-build-dependencies-release | 46 | 28 | 53 | In progress; [findings](audit-coverage/P01-findings.md) |
| P02-wire-dispatch-lifetime | 18 | 16 | 18 | In progress; [findings](audit-coverage/P02-findings.md) |
| P03-storage-setup-authorization | 16 | 15 | 15 | In progress; [findings](audit-coverage/P03-findings.md) |
| P04-bitcoin-signing | 15 | 13 | 13 | In progress; [findings](audit-coverage/P04-findings.md) |
| P05-evm-signing | 26 | 21 | 22 | Pending |
| P06-other-chain-signing | 53 | 45 | 53 | In progress; Ripple findings in [ledger](audit-coverage/P02-findings.md) |
| P07-provider-solana-trust | 12 | 5 | 9 | Pending |
| P08-zcash-cryptography | 6 | 0 | 6 | Pending |
| P09-entropy-authentication | 27 | 12 | 16 | Pending |
| P10-ui-platform | 31 | 19 | 29 | In progress; backup acknowledgement finding in [ledger](audit-coverage/P02-findings.md) |

## Reconciled staged product comparisons

These are prospective complete product surfaces at the staged audit tips, not
claims that those tips are canonical or accepted. Initial inventory anchors remain
in each JSON's initial_inventory. Canonical heads are recorded separately.

- 7.14.2: staged head `b08a68717c46af3204457149580986fe2682a707`, merge base `da075b8cb717b56dc1023edb52c2ccdf171b8a08`;
  [path ledger](audit-coverage/7.14.2.json), 353 paths.
- 7.14.3: staged head `684a2771483ee80b49fa29fa081d95799d5610c9`, merge base `1af2ffe7de1a40780b78b0be3807a140f9de0dd0`;
  [path ledger](audit-coverage/7.14.3.json), 201 paths.
- 7.15: staged head `b57eb71c2ee1babfeb20805b7f6b64ad70c4e925`, merge base `1af2ffe7de1a40780b78b0be3807a140f9de0dd0`;
  [path ledger](audit-coverage/7.15.json), 286 paths.

Every current path has a candidate blob identity. Existing reviewed entries with
matching explicit reviewed blobs retain that binding. Reviews whose identity was
only described in narrative need evidence binding, not automatic whole-file
rediscovery. A changed reviewed blob reopens only the affected delta. Paths no
longer differing from the comparison base remain recorded as interaction evidence.
No pending entry is closed by this reconciliation or by green CI.

## Phase execution contract

1. Stage each phase on fork develop or its frozen predecessor; retain small
   audit PRs for coherent review units and canonical release PRs as product views.
2. Record exact reviewed hunks and implementation identities. Read dependent
   consumers and failure paths, then record findings with a concrete failure trace.
3. Fix and test each actionable finding, audit the fix and affected interactions.
4. Complete the cross-phase review of dispatch, authorization, signing, persistence,
   UI disclosure, dependency compatibility and release/build provenance.
5. Reassemble, validate, record remaining external gates and update canonical
   branches. Declare readiness only after every path/phase has a supported disposition.

Prior assembly CI and unit receipts remain evidence only for their named checks.
They do not populate pending review entries automatically. No Copilot in this phase.

## Closing and refreshing coverage

The comparisons above bind the named staged candidates. Before subsequent batch or
release acceptance, reconcile paths against the actual candidate and recorded
comparison base, including new remediation files, deletions and dependency
changes. Retain prior reviewed blob/hunk identities and evidence; explicitly
review changed deltas and affected interactions. Never convert an unread path
to reviewed based on a green test or matching filename.

A phase closes when every current path/hunk has a supported disposition, its
required interactions have been reviewed, actionable findings are resolved in
the candidate, and required evidence is recorded. A phase may close before its
accepted units are integrated; report integration separately. Reopen only under
the evidence-based triggers in the rehearsal SOP. The acceptance checklist links
these ledgers rather than maintaining a competing finding inventory.

## Scope-repair comparison supersedes the historical heads above

JSON ledgers now bind #754 (8c13ed24f), #755 (0fe01bc1b), and #756 (bd5e509cd),
with prior comparison saved as pre_scope_repair_inventory. Changed blob identities
require delta evidence binding; no unread path is closed. See
[scope-repair.md](audit-coverage/scope-repair.md) for the withdrawn acceptance.
Canonical integration and whole-release acceptance remain separate and pending.
