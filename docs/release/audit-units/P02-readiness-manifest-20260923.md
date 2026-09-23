# P02 final-review readiness batch

User authorization: 2026-09-23, work until P02 is ready for final Copilot.
This prepares readiness; it does not request the final external review.

## Frozen inputs

- Prior P02 receipt: `a6a8b6d73a297ac28181dfcc6e77a1c63ac9b0a6`.
- Tested P02 code: `3ade6134877314293749af4e73de9ebf9d9de0c4`.
- Original code-bearing Stack 02: `51411c4a7c96137bc80f8b99fa1690c4e385f7fd`.
- Stack 01 current head: `cec3cac2487356e0ffa556d201e5eab14f31e054`, not yet accepted.
- Stack 00b current head: `4c56e19e3070772a28b2890a4ec862ecf77d5429`, separately claimed and not accepted.
- Local remediation sources: Bitcoin progress `2831f91b5`; selected progress and approval policy changes in `ae4061a6f`. Do not replay the combined remediation branch or its unpublished host dependency pointer.
- All dependency pins stay at the prior receipt's exact values unless separately justified.

## Finite work and dependency order

1. Resolve P02-I02's four progress failures as a named workflow-progress interaction unit. Preserve the rule that accepted continuation work renews the timer, while feature polling, malformed packets, empty recovery deletion and empty EOS chunks do not. Ordinary full and Bitcoin-only tests must execute applicable regressions.
2. Reconcile the padded-zero unlimited-approval failure against the declared product policy and pinned host expectations. Record its disposition independently of the progress unit; no security contract is changed merely to make a test pass.
3. Resolve P02-I03's repeat-run recovery fixture failure. Trace storage erase versus RAM reset and test against an already initialized emulated image. Preserve assertions proving an all-space recovery cannot commit a mnemonic.
4. Reconcile the Stack 01/02 progress-policy conflict on an isolated candidate. Preserve tested predecessor fixes and all five P02 contracts. Claim no predecessor acceptance on another owner's behalf; do not restack a shared branch without recording the reconciled head and scope.
5. Validate final applicable native, host, storage, ARM/resource, report and CI gates. Freeze a code-bearing review identity, complete report/PDF and final adjacent inventory. Keep physical/release gates and actual Copilot delivery separate.

## Scope and status

This explicit scope extension addresses the blockers found by the P02 audit; it is not a full chains-feature or whole-alpha audit. Separate coherent commits and finding dispositions are required for progress, approval policy and recovery fixture changes. Current status: in progress. No Copilot request, shared-branch reset, upstream merge or release publication is authorized by this manifest.

## Approval policy disposition

The global unlimited ERC-20 refusal is an existing release-line contract, visible in `a56fb3e88:lib/firmware/ethereum.c` and independently required by the pinned host `49d537ce953b7524599bfc87f56b7a50a51a13a1` test `test_msg_ethereum_clear_signing.py` (`erc20-approve-unlimited`). Restore that refusal before generic confirmation. Canonicalize all-zero native value representations so a 32-byte zero cannot bypass the ERC-20 classifier. This is a separate inherited policy repair, not evidence that the entire chains feature set is accepted.

Progress and recovery focused verification: 19 native tests passed twice consecutively with the existing emulator image. Full-suite repeated-image verification remains required.

## Predecessor reconciliation

Merge the exact Stack 01 head `cec3cac2487356e0ffa556d201e5eab14f31e054` into the isolated readiness branch. Preserve its UDP animation fix, board regression and response callback API. Firmware uses explicit validated progress calls instead of subscribing to all continuation responses: empty recovery deletes and empty EOS chunks can emit requests without making progress. Preserve continuation renewal in Bitcoin, Ethereum, recovery, EOS, Cosmos, Osmosis, Binance, Thorchain, Mayachain, Tendermint and reset. The latter handlers emit continuation requests only after successful initialization or validated message updates; add explicit renewal at those sites.

Preserve predecessor parser-level feature-polling and home-screen response regressions. Its synthetic TxRequest-only renewal test is superseded by the actual validated Bitcoin stream test: emitting a response alone is no longer the firmware progress contract. This reconciliation does not confer acceptance on either predecessor owner.

## Subsequent Stack 01 remediation

The live predecessor advanced to `23b3c16b1b43e50ff04d8c5e4a77ee37c4a8e393` following its own authorized review. Reconcile this exact head locally before claiming current-predecessor readiness. Retain P02's shared short-packet rejection helper and import the fresh-poll rejection-latch reset plus `USBRX.MalformedTinyFrameUnwindsAndNextPollRecovers`. Preserve both original and new tiny-wait regressions.

Import dice-mode initialization before entropy draw and DebugLink omission of dice entropy. The Zcash conflict is technically superseded: Stack 02 already draws an 80-byte transcript using both health checks, erases it on all paths, and uses the stronger `_with_ak` API that verifies host rk while preserving dummy-spend behavior and progress callbacks. Keep that implementation; replaying the predecessor's older signer call would discard these later contracts. No crypto pin change is required. Predecessor acceptance remains pending.
