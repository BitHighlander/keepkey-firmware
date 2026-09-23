# P02 internal remediation round 2

Status: in progress; no additional Copilot request authorized or made.
Baseline: 5a59d8a5edcf78be56c969f15aea8afcfd9afa3d, PR #855.
Review: 5288422597, eight inline findings plus body observations.

## Contract and scope

The sensitive values are the device draw, roll sequence/digest and derived
mnemonic. During an active dice ceremony, including before setup is armed,
DebugLinkState returns no fields: bytes, word encodings, canvas pixels and
stored-secret aliases are all covered. Debug memory reads are refused too.
On-device words and digest remain available for offline verification. Abort and
commit wipe transient secrets and the old display before releasing the gate.
After completion DebugLink resumes its privileged stored-wallet diagnostics;
this is a ceremony privacy boundary, not a claim that a debug build protects a
committed wallet from its diagnostic host. Shipping debug exclusion is checked
separately. BOTH full and Bitcoin-only variants are in scope.

Necessary harness scope change: the pinned python-keepkey tests previously read
forbidden device words and digest to build their oracle. Update that dependency
on a dedicated published branch, retain legacy behavior for older candidates,
and select the strict profile with KK_DICE_DEBUG_PRIVATE=1. Do not weaken or
skip required wire execution. In the strict profile private dice screenshots
are unavailable by design; native known-draw fixtures verify the device-side
logical word pages and the complete reset derivation. Physical display review
remains a release qualification. The host test independently verifies ONLY
from injected rolls and the committed mnemonic; it cannot independently recover
the MIXED device draw. The native fixture is required for that claim.

## Findings inventory

| Finding | Required disposition/evidence | Status |
| --- | --- | --- |
| 4080313772 + MIXED body note | Whole-state dice gate, getters, phase wire checks, independent derivation fixture, abort/restart | Implemented; validation ongoing |
| 4080313826 Binance | Real initial and continuation renewal; malformed/polling expiry | Focused tests pass |
| 4080313868 Cosmos | Same | Focused tests pass |
| 4080313908 Mayachain | Same | Focused tests pass |
| 4080313951 Osmosis | Same | Focused tests pass |
| 4080313992 Tendermint | No generic wire map exists; incoming generic request rejection/expiry tested; no protocol activation | Focused test passes; technical disposition |
| 4080314042 Thorchain | Real initial and continuation renewal; malformed/polling expiry | Focused tests pass |
| 4080314092 reset | Renewal is at initial EntropyRequest, not EntropyAck; test actual reset dispatch at expiry | Focused test passes |
| EOS body note | Actual EosSignTx renewal plus existing chunk/empty-chunk tests | Focused tests pass |
| USB callback body note | Production callback source compiled with endpoint mock: short, complete, zero, error, buffer wipe, both endpoints | Focused tests pass |
| DebugLink latch body note | Clear rejection scope around normal debug dispatch, retain protected-wait rejection | Focused test passes |
| Wording body notes | Protected-wait message and precise disclosure contract; obsolete readiness claims superseded | In progress |

Do not mark findings resolved or readiness complete until final tests, mutation
controls, source review and evidence reconciliation are complete.

## Predecessor refresh during this round

Live Stack 01 advanced from `23b3c16b1` to
`6b923be9993edfa7b072c56e87626374ba030f75` (commits `8952feb39` and
`6b923be99`). Reconcile storage downgrade refusal at setup commit and dispatch,
v2 metadata native-value approval/reset, order-independent RNG fixtures, compose
build failure propagation, Zcash native execution and explicit privacy-OFF build
support. Existing P02 Hive/Zcash registration and stronger timeout regressions
are retained where predecessor formatting patches conflict. Remove the P02
unconditional duplicate zcash.c source so privacy-OFF actually excludes it.

Do not import the predecessor's Ripple memo refusal removal: this P02 candidate
still declares `ripple-memo-policy` unavailable and retains the existing refusal
contract. Do not replace the report with the predecessor's receipt. Apply its
Zcash full-product native-report requirement and additionally require the dice
native and wire assertions introduced here. This is an assessed reconciliation,
not acceptance or a rewrite of the shared predecessor/release branches.

Host harness pin: `ea385cf6fdd5c22e2c3ea3845787777fb9c9d127`, published at
`keepkey/python-keepkey`, branch `audit/p02-dice-debug-privacy-20260923`.
