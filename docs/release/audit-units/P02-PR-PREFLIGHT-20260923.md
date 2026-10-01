# P02 proposed review preflight — 2026-09-23

Status: preparation only; external-review entry gates remain open. No Copilot request or final review PR has been created.

## Frozen integration inputs

- Fork repository: `BitHighlander/keepkey-firmware`.
- Candidate branch: `audit/p02-review-readiness-20260923`.
- Code/test integration head: `f5a6fe70c` (resolve to the full SHA in the readiness receipt).
- Adjacent remediation base: `51411c4a7c96137bc80f8b99fa1690c4e385f7fd`, branch `release/715-stack-02-chains`, PR #832.
- Integrated predecessor: `23b3c16b1b43e50ff04d8c5e4a77ee37c4a8e393`, PR #831; its owner's acceptance remains pending.
- Earlier candidate `ecd5705e42555060ee103d2b0d7089532593c1f9` passed every required job in CI run 35830189708. The newer predecessor merge changes firmware and tests, so that run is supporting evidence only.
- The final report-containing head must be supplied in the eventual PR body. A receipt cannot contain its own commit hash.

## Code-bearing coverage

The canonical `scripts/release/check-code-review-diff.sh` passes for the exact remediation base and code head, logged as `predecessor2-code-bearing.log`. This proves eligible changed paths exist; it does not establish delivered review or full feature acceptance.

| Review unit | Changed paths / provenance | Required inherited review |
| --- | --- | --- |
| P02 transport and credential lifetime | messages.c, usb.c, confirm_sm.c, pin_sm.c, passphrase_sm.c, fsm_msg_common.h, fsm.cpp, storage_passphrase.cpp, usb_rx.cpp, test_p02_transport.py; original remediation 5e20b18c1 through 3ade61348, plus predecessor fresh-poll reset | Existing wiping and Initialize policy, raw and normal dispatch hooks, USB/UDP/U2F framing, all tiny wait exits |
| Validated workflow progress | signing.c, ethereum.c, recovery_cipher.c, EOS and six chain handlers, reset.c, fsm tests; 2b7054cbb, 4ae9f84ef, 0646ae6eb | Home/screensaver state, failure returns before renewal, empty recovery/EOS cases and predecessor animation |
| Existing unlimited-approval policy | ethereum.c and padded-zero regression; 518608729 | ERC-20 classifier bounds, finite approvals, generic-signing fallback and pinned host policy expectation |
| Predecessor interaction | fresh-poll latch reset and dice DebugLink omission; f5a6fe70c | Preserve later Zcash checked nonce / rk verification; don't replace it with predecessor's older signer call |

The recovery fixture reset is supporting test infrastructure, not a production storage-policy change. Report-only commits and checksum allowlisting do not claim firmware review by themselves. Final upstream-shaped PRs must preserve the independently explainable unit separation above; do not use one broad-product diff as their substitute.

## PR body requirements

Copy the final containing SHA, immutable base and report-generation predecessor from the sealed receipt. Link the source report/PDF, skip inventory, artifact manifest, exact-head CI, predecessor receipts and finding dispositions. Include the full final adjacent numstat inventory and label inherited-code coverage. State zero P02 Copilot requests and no physical/release acceptance. Recheck live target SHA before submission; do not silently update the accepted base or conceal new predecessor changes.

## Entry checklist

- Local native, host, storage, ARM/SRAM, formatting and report evidence: see current readiness receipt; refresh for the new predecessor.
- Code-bearing machine gate: passed for frozen code range; repeat on final report-containing head.
- Source/PDF equality, opened rendered pages and stable complete numstat: required when sealing the final report.
- Live target agreement and final PR body agreement: pending final upstream-shaped target selection after internal acceptance.
- Current exact-head CI: pending for the new predecessor integration.
- Accepted predecessor sequence and internal release acceptance: pending.
- Late external checkpoint authorization: pending under the canonical SOP. The user's readiness goal authorizes preparation, not an early review request.

Until these pending gates close, the code-review checkpoint remains unverified. Receipt-only PR #850 supplies no firmware-code review evidence.
