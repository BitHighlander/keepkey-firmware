# Fork release product program

Owner direction: 2026-09-08. Assemble and harden all three canonical products,
using small audit PRs and finite acceptance contracts. Follow
[REHEARSAL-SOP.md](REHEARSAL-SOP.md). No merges into fork develop, no Copilot during
internal rehearsal, no upstream publication or release signing.

## Objective and finish line

Owner correction: assembly and passing CI do not complete the requested audit.
The three assembled releases are baselines, not yet accepted for the final
Copilot checkpoint. Audit every release PR change in bounded phases, review
cross-phase interactions, resolve actionable findings, re-audit fixes, and rerun
appropriate validation. Record exact file/hunk coverage and evidence; existing
passes may be reused only for unchanged, actually reviewed scope.

The finish line is complete phase coverage and no unresolved actionable findings
across all three releases. Do not equate green builds or absence of previously
known defects with a completed review. A future Copilot zero-finding result is
the target, not a guarantee. Keep release-product PRs into fork develop unmerged
and dependent phase PRs on frozen predecessors. Copilot remains deferred.

The active goal has been reopened to cover this full audit. Prior assembly
receipts remain valid test evidence; their readiness claims are superseded by
this correction and the phase coverage ledger.

## Execution control

Use [RELEASE-ACCEPTANCE-CHECKLIST.md](RELEASE-ACCEPTANCE-CHECKLIST.md) for the
remaining work and milestone order. First prove internal acceptance of 7.14.2,
then 7.14.3 and 7.15, carrying applicable shared fixes across products. The SOP
requires an assembly checkpoint after each phase or three accepted units.
The tables below are dated evidence snapshots, not live CI status; refresh exact
heads and terminal results before making readiness claims.

## Canonical products and current evidence

| Product | Canonical fork branch / product PR | Current canonical head | Internal status |
| --- | --- | --- | --- |
| 7.14.2 | [release/7.14.2](https://github.com/BitHighlander/keepkey-firmware/tree/release/7.14.2), [#650](https://github.com/BitHighlander/keepkey-firmware/pull/650) | `dedfd7e407a2e17a7a6e7312fb86d7a4deb32b54` | B01 integrated through 02349bf77; durability/signing fixes and full acceptance pending |
| 7.14.3 | [release/7.14.3-bitcoin-only](https://github.com/BitHighlander/keepkey-firmware/tree/release/7.14.3-bitcoin-only), [#627](https://github.com/BitHighlander/keepkey-firmware/pull/627) | `47eae604e183ab1c6c69be7dae43eee60b58326c` | Prior validated integration; subsequent audit fixes pending integration |
| 7.15 | [release/7.15](https://github.com/BitHighlander/keepkey-firmware/tree/release/7.15), [#629](https://github.com/BitHighlander/keepkey-firmware/pull/629) | `f20c2497a0990a6690c5bb804414c11cac74bf58` | Prior validated integration; subsequent audit fixes pending integration |

Fork develop remains `da075b8cb717b56dc1023edb52c2ccdf171b8a08`. All three
product PRs target it and remain unmerged. A product PR is the cumulative
integration view; each audit PR targets its immediate predecessor so its diff
remains bounded. The dirty alpha worktree is preserved.

The receipts are `docs/release/<version>-COMBINED-CANDIDATE.md` on each product.
They supersede status snapshots copied into a candidate before assembly.

## Current audit stack tips

Verified against fork refs on 2026-09-08. These branches contain later audit
fixes and are not yet the canonical release products above. Each PR targets its
frozen immediate predecessor; no develop merge is involved.

| Product | Audit tip | Head | Current validation |
| --- | --- | --- | --- |
| 7.14.2 | [Current audit draft, #740](https://github.com/BitHighlander/keepkey-firmware/pull/740) | `d4c23c9d53551c62c6b18f00a8902da4796c7a64` | Native: 162 pass; host: 434 pass / 47 skip; migration: 4 pass. CI 34313676228 succeeded; full audit acceptance pending. |
| 7.14.3 | [Current audit draft, #739](https://github.com/BitHighlander/keepkey-firmware/pull/739) | `c8f47fce78337aaa0ccd18cf35ea575f8e49827e` | Native: 197 full / 97 BTC pass; host: 537/218 full and 309/446 BTC pass/skip. CI 34313363985 succeeded; full audit acceptance pending. |
| 7.15 | [Current audit draft, #742](https://github.com/BitHighlander/keepkey-firmware/pull/742) | `039e2f9644876443ad1c5ad78082cee0e8901cba` | Native suites: 507 full / 99 Bitcoin-only pass. Local ARM resource correction passes with 16,412-byte reserve. Host: 727/30 full and 314/443 BTC pass/skip. CI 34312975959 succeeded; full audit acceptance pending. |

The P03 findings ledger records scope, applicability, regressions and limitations.
Prior migration-test receipts using the emulator without sector erasure were
withdrawn and replaced by corrected-model checks. Passing builds do not close the
remaining phase inventory or cross-phase review. No product is ready for Copilot.

## Historical validated candidate receipts

- 7.14.2: code `34e7c236d`, [CI 34277705965](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34277705965)
  passed every required gate. Native suites and 433 host tests pass; 47 documented
  skips. ARM reserve 22,508 bytes. Final canonical commit adds documentation only.
- 7.14.3: code `b51024d37`, [CI 34277705868](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34277705868)
  passed both ARM/integration variants and both aggregate gates. Local Bitcoin-only
  host suite: 307 passed, 445 variant/policy skips. SRAM reserve: full 21,312 bytes,
  Bitcoin-only 28,268 bytes. Final canonical commit adds documentation only.
- 7.15: validated code `af6c0bfcf96234499a9412136fa59a4108b3d9c9`,
  [CI 34283763680](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34283763680)
  passed every required job, both variants, shared-library integration, report
  validation and CI gate. Canonical receipt `a18317f88` changes documentation only.
  Native full: 498 firmware, 13 board, 18 crypto, 6 Pallas and 72 Zcash tests.
  Native Bitcoin-only: 92 firmware, 13 board and 18 crypto tests. Local host:
  724 full / 31 skips and 312 Bitcoin-only / 443 skips, including owned-process
  lifetime and storage checks. CI host: 719 full / 36 skips and 307 Bitcoin-only /
  448 skips; its extra five skips per variant are covered locally. CI screenshot
  suites pass, with separate local lifetime/additive evidence in 36 PNGs. Both ARM
  manifests and all 23 binary/ELF hashes per variant are verified. SRAM reserves:
  full 16,392 bytes (only 8 above the floor), Bitcoin-only 31,424 bytes.
  PR #666 consolidated adjacent PIN conditions. PR #667 closes the CI-exposed
  debug backup acknowledgement race with a deterministic red/green regression.

## Frozen source identities

Original 7.14.2: `cdde6888c2792cd9c673d0ff47f0cdb8069e08dc`.
Original 7.14.3: `abe29d1288638867dc64dfe04219b89f7a593133`.
Original 7.15: `a56fb3e88d7dbbe31a321179c10a8fd2023d8f0c`.
Alternate 7.15.0: `e601d2df8f5a847e3d3c297c8d60aba65cb4b579`.
The alternate is reconciled by behavior, not merged wholesale or renamed into a
fourth product. Existing F00–F05 PRs #635–#640 remain historical rehearsal evidence.

## Accepted audit work

- Shared: unsigned storage decoding where missing; exact nanopb capacities and
  terminal transport rejection; storage buffer capacities; passphrase transitions;
  cipher scratch cleanup; EOS authorization disclosure; low-level workflow
  revocation; generated token byproducts.
- 7.15: provider icon placement; restored FSM coverage; authenticator credential
  source wipe; Zcash teardown, viewing-key consent and account identity; shared
  native test bootstrap; duplicate-detector positive observation.
- Host: exact decode rejection contract; owned-emulator network leases;
  variant-aware storage power cycles; independently verified EOS vector;
  Zcash applicability; full canonical provider/LUT/lifetime/recovery/entropy
  capability coverage and current Uniswap approval-policy expectations.

Each unit has its own receipt under `docs/release/audit-units/` on the candidate.
Earlier token-table failures were caused by an uninitialized nested data source
and closed after exact dependency initialization; no token behavior was altered
for those failures. The older unknown-storage lockout was superseded by the
current explicit downgrade-erasure policy, and the uncommitted replay was withdrawn.

## Full phased audit in progress

See [PHASED-AUDIT-COVERAGE.md](PHASED-AUDIT-COVERAGE.md). All three products
require complete recorded review coverage before readiness can be declared.
Prior bounded fixes remain evidence for those specific changes, not a substitute
for auditing the full release surface. The goal stays active through phased
review, remediation, interaction review and final assembled validation.

Final physical OLED and signed-upgrade checks are not performed here. The external
provider tooling's test-key disposition remains a release deliverable, not an
excuse to change firmware trust anchors. Upstream preparation uses the accepted
receipts to stage final small fork PRs, reconcile public dependencies and perform
the deferred Copilot review before upstream PR creation.

## Overnight B01 checkpoint

Canonical 7.14.2 advanced by verified fast-forward to dedfd7e407a2e17a7a6e7312fb86d7a4deb32b54.
The candidate receipt accepts the bounded batch through 02349bf77, independently
verified against CI 34299743827 and all 23 ARM artifact hashes. Complete release
coverage is not reconciled yet. Durability remains outside this batch because
installed-bootloader execution/compatibility evidence is open. Later signing fixes
remain on the existing predecessor stack. The receipt commit changes no code or
pins; future assembly must carry it forward without replaying old readiness text.
Develop remains da075b8cb717b56dc1023edb52c2ccdf171b8a08.

Current staged change-path units supersede the audit-tip snapshot above:
7.14.2 #745 ebf0eb500, 7.14.3 #744 44d0c60c1, 7.15 #743 a1e7f5315.
Complete native suites pass 163 / (198 full, 98 BTC) / (508 full, 100 BTC).
New-head host/ARM checks remain pending; predecessor green CI is not new-head
acceptance. P04-003 records exact scope and evidence. No tracked local firmware
changes remain from the previously interrupted change-path unit.

Current batch after B01: #750 b08a68717 (7.14.2), #749 684a27714 (7.14.3),
#751 b57eb71c2 (7.15). Includes P04-003, bootloader replay export and P04-004.
Reconciled prospective PR inventories contain 353 / 201 / 286 paths. Most remain
pending; this is scope accounting, not audit completion. Named bootloader 2.1.4
protection routines preserve all 17 snapshots in all five builds with 799 controls
each; broader physical/older-loader applicability is not implied. Complete native
passes 164 / (198,98) / (508,100); host preflight and next assembly are pending.
Corrected P04-003-only 7.14.2 CI 34411206889 is running on 875af590e; newer batch
production has the additional rejected-history fix and needs its own validation.
