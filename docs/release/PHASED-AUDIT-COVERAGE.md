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
| P00-scope-documents | 96 | 14 | 38 | Pending |
| P01-build-dependencies-release | 46 | 28 | 53 | Pending |
| P02-wire-dispatch-lifetime | 17 | 11 | 17 | Pending |
| P03-storage-setup-authorization | 16 | 15 | 15 | Pending |
| P04-bitcoin-signing | 14 | 13 | 13 | Pending |
| P05-evm-signing | 26 | 21 | 22 | Pending |
| P06-other-chain-signing | 53 | 45 | 52 | Pending |
| P07-provider-solana-trust | 12 | 5 | 9 | Pending |
| P08-zcash-cryptography | 6 | 0 | 6 | Pending |
| P09-entropy-authentication | 27 | 12 | 16 | Pending |
| P10-ui-platform | 33 | 19 | 29 | Pending |

## Frozen product comparisons

- 7.14.2: head `c72672f06b3bc568183280607d9c3bc8a6245176`, merge base `da075b8cb717b56dc1023edb52c2ccdf171b8a08`;
  [path ledger](audit-coverage/7.14.2.json), 346 paths.
- 7.14.3: head `de0251bbdb286ccdc786a5513ebc94bddd890e3f`, merge base `1af2ffe7de1a40780b78b0be3807a140f9de0dd0`;
  [path ledger](audit-coverage/7.14.3.json), 183 paths.
- 7.15: head `a18317f8869bb905cac9322f0d76ca7aacbaf544`, merge base `1af2ffe7de1a40780b78b0be3807a140f9de0dd0`;
  [path ledger](audit-coverage/7.15.json), 270 paths.

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
