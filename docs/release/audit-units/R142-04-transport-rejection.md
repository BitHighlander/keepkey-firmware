# R142-04: transport rejection terminates active workflows

Base: audited foundation `843a01ff2`. Scope: transport failure callback and the
companion host regression; preserve normal chain error handling and wire errors.

Exact nanopb byte bounds reject an oversized multisig signature before its chain
handler executes. The handler's abort therefore never runs. Reproduction on the
assembled F05 binary: decode returns UnexpectedMessage, but a subsequent TxAck
returns a signer input error instead of rejecting an inactive session. The
existing CI test stopped at its obsolete SyntaxError expectation and hid this
second failure. Foundation CI run 34270267435 passed ARM, static analysis and
unit builds, but failed this integration test.

The transport callback now aborts workflows, returns the UI home, and sends the
original failure in both debug and production builds. Direct chain-handler
fsm_sendFailure calls are unchanged. The companion test asserts the exact decoder
error and retains terminal rejection of a follow-up packet; no broad failure-code
allowlist or weakened terminal assertion is used.

Validation: the updated test failed on the prior assembled binary (follow-up code
9 rather than 1) and passed with this firmware delta. Both signing-boundary tests
passed and all 269 assembled firmware unit tests passed. This local run used F05
`1867e590d` plus the exact callback delta, with native host build accommodations
previously documented; it is interaction evidence, not a complete F00 release
receipt. Exact-head ARM and full integration checks remain required.

Logs: `/private/tmp/7142-nanopb-boundary-repro.log`,
`/private/tmp/7142-transport-boundary-tests.log`, and
`/private/tmp/7142-transport-firmware-tests.log`.

Companion python pin: `c6c8a901b030a3a525637433a5c2c329cd212187`.
No Copilot requested. Reconcile this unit into the audited foundation and assess
all three release products before acceptance.
