# Fork release product program

Owner direction: 2026-09-08. Assemble and harden all three canonical products,
using small audit PRs and finite acceptance contracts. Follow
[REHEARSAL-SOP.md](REHEARSAL-SOP.md). No merges into fork develop, no Copilot during
internal rehearsal, no upstream publication or release signing.

## Objective and finish line

Finish when every declared product capability is accounted for, known applicable
findings are closed or explicitly superseded, required internal checks pass, and
validated candidates are on the canonical fork branches with exact receipts.
“Perfect” means that contract is met with no known unresolved in-scope defects;
it does not mean endless whole-tree discovery or a proof of zero possible bugs.
Physical release-signing requirements and the final Copilot checkpoint remain
separate, explicit gates.

The goal tool rejected replacing the older unfinished usage-limited goal. This
manifest records the requested expanded objective without falsely completing it.

## Canonical products and current evidence

| Product | Canonical fork branch / product PR | Current canonical head | Internal status |
| --- | --- | --- | --- |
| 7.14.2 | [release/7.14.2](https://github.com/BitHighlander/keepkey-firmware/tree/release/7.14.2), [#650](https://github.com/BitHighlander/keepkey-firmware/pull/650) | `c72672f06b3bc568183280607d9c3bc8a6245176` | Accepted and advanced; ready for the later Copilot checkpoint |
| 7.14.3 | [release/7.14.3-bitcoin-only](https://github.com/BitHighlander/keepkey-firmware/tree/release/7.14.3-bitcoin-only), [#627](https://github.com/BitHighlander/keepkey-firmware/pull/627) | `de0251bbdb286ccdc786a5513ebc94bddd890e3f` | Accepted and advanced; both source variants validated |
| 7.15 | [release/7.15](https://github.com/BitHighlander/keepkey-firmware/tree/release/7.15), [#629](https://github.com/BitHighlander/keepkey-firmware/pull/629) | `a56fb3e88d7dbbe31a321179c10a8fd2023d8f0c` | Final combined candidate `af6c0bfcf` under validation; not yet advanced |

Fork develop remains `da075b8cb717b56dc1023edb52c2ccdf171b8a08`. All three
product PRs target it and remain unmerged. A product PR is the cumulative
integration view; each audit PR targets its immediate predecessor so its diff
remains bounded. The dirty alpha worktree is preserved.

The receipts are `docs/release/<version>-COMBINED-CANDIDATE.md` on each product.
They supersede status snapshots copied into a candidate before assembly.

## Validated candidates

- 7.14.2: code `34e7c236d`, [CI 34277705965](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34277705965)
  passed every required gate. Native suites and 433 host tests pass; 47 documented
  skips. ARM reserve 22,508 bytes. Final canonical commit adds documentation only.
- 7.14.3: code `b51024d37`, [CI 34277705868](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34277705868)
  passed both ARM/integration variants and both aggregate gates. Local Bitcoin-only
  host suite: 307 passed, 445 variant/policy skips. SRAM reserve: full 21,312 bytes,
  Bitcoin-only 28,268 bytes. Final canonical commit adds documentation only.
- 7.15: `rehearsal/715-combined-product` at `af6c0bfcf96234499a9412136fa59a4108b3d9c9`;
  [final CI 34283763680](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34283763680)
  is pending. PR #666 consolidated adjacent PIN conditions. The subsequent CI
  exposed a debug backup subpage retaining the previous acknowledgement; PR #667
  clears it for each new request and proves the fix with a deterministic
  before/after regression. Complete native suites pass (498 full firmware tests), including restored
  FSM registration, shared board bootstrap and D-01 positive duplicate-detector
  evidence. Host pin `08e491c60fe36110598a3791b2441644fcf55f76` restores the actual
  capability matrix: full suite 724 passed / 31 classified skips / 165 subtests;
  Bitcoin-only 312 passed / 443 variant or policy skips / 104 subtests. Owned
  emulator power-cycle and additive-review evidence includes 36 captured PNGs
  across four passing scenarios. Canonical promotion still awaits CI and artifacts.

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

## Remaining program work

Finish 7.15 exact-candidate CI, inspect its full/Bitcoin-only artifacts and skips,
record the receipt and advance its canonical branch normally. Then reconcile the
final program table and product PR descriptions. No further broad discovery or
feature import is planned. Only a concrete failed contract or missing required
evidence can reopen a frozen candidate.

Final physical OLED and signed-upgrade checks are not performed here. The external
provider tooling's test-key disposition remains a release deliverable, not an
excuse to change firmware trust anchors. Upstream preparation uses the accepted
receipts to stage final small fork PRs, reconcile public dependencies and perform
the deferred Copilot review before upstream PR creation.
