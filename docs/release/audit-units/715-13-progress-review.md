# Block 13 progress and Osmosis review — 2026-09-27

This is working evidence for S13-005/S13-006, not combined block acceptance.
Base checkpoint: `123bb0335e382a3b206ad05d25e7b924289f1e1e` plus the current
uncommitted block repairs. Final Stack 11/12 integration, immutable evidence
identity, hosted qualification and physical-device acceptance remain separate.

## Reachability and scope reconciliation

| Workflow | Full-feature entry | BTC entry | Disposition |
| --- | --- | --- | --- |
| Binance | `messagemap.def`: SignTx and TransferMsg; Binance coin entry remains present | Excluded | Initial and continuation hooks; real USB receive tests |
| Cosmos | `messagemap.def`: SignTx and MsgAck | Excluded | Initial and continuation hooks; real USB receive tests |
| Osmosis | `messagemap.def`: SignTx and MsgAck | Excluded | Initial and continuation hooks plus send amount gate; real USB receive tests |
| THORChain | `messagemap.def`: SignTx and MsgAck | Excluded | Initial and continuation hooks; real USB receive tests |
| MAYAChain | `messagemap.def`: SignTx and MsgAck | Excluded | Initial and continuation hooks; real USB receive tests |
| Generic Tendermint | Handlers are textually included in `fsm.c`, but **no incoming or outgoing message-map entries** | Excluded | Direct handler tests only; USB rejection separately pinned. Do not call this a working wire protocol. |
| Reset | ResetDevice / EntropyAck map and reset implementation | Included | Initial and accepted-entropy phase hooks; real USB receive tests |

All six compiled coin handlers now call `note_workflow_progress()` after
successful initialization and before their initial request. Continuation hooks
run only after the selected message passes validation, review, and the signer
update, when another message is outstanding. Failed initialization, missing or
invalid payload, declined review, and status polling do not execute the hook.
Successful final-message signing is synchronous and returns a completed result;
these hooks cover waits for the host, not a lease on a completed signer.

Binance is reachable in this source snapshot despite broader retirement
assumptions. Generic Tendermint is not mapped. No wire family was re-enabled.

Bitcoin, Ethereum, EOS and accepted recovery edits already route through
progress hooks. The additional missing initial hook in recovery initialization
was reported to the recovery owner: it ended in `setup_arm(SETUP_RECOVERY)` and
`next_character()` without an explicit accepted-initial-stage hook. Its physical
confirmation can provide user activity, but that is distinct from an explicit
workflow phase invariant. Recovery changes and their evidence live with that
owner and are not counted in this file's 38-test receipt.

## Osmosis policy and host reconciliation

The wire amount is a decimal **string**, and pinned Python MsgSend currently
uses `str(coin['amount'])`, not a uint64 protobuf field or bounded Python
conversion. The uint64 limit is the audited send policy represented by the
existing 7.15 capability-gated host rejection test
`test_msg_osmosis_signtx.py::test_osmosis_send_rejects_noncanonical_wire_amounts`.
It must not be justified by claiming the current host API enforces the bound.

`osmosis_validate_send_amount()` first retains the existing required-string,
decimal-digit and canonical-leading-zero checks. A length/lexicographic bound
then accepts `18446744073709551615` and rejects larger values, without a parsing
conversion or saturation. Send amount/denom failures return SyntaxError with
`Invalid Osmosis amount or denomination` before a review screen, matching the
existing host capability contract. Address rejection and denomination display
are otherwise unchanged.

The shared `osmosis_validate_amount()` is unchanged. Pool shares and swap
amounts retain their wider decimal-string domain, which is tested above uint64.
This is a send-only policy, not a claim that Osmosis SDK integers in general
are uint64.

## Reset phase semantics

Missing entropy and present-but-empty entropy are both legal host replies:
`fsm_msgEntropyAck()` already passes null/zero or a zero-length buffer into
`reset_entropy()`. In the normal mode the device draw remains a hash input;
in dice modes host bytes are deliberately ignored so offline derivations stay
valid. All three forms (missing, empty, nonempty) advance an armed reset to
backup review exactly once.

The progress hook is after `setup_require(SETUP_RESET)` and before that phase
transition. The synchronous continuation either completes setup or aborts it
before returning. A stale EntropyAck then receives UnexpectedMessage and cannot
renew the deadline. Tests decline backup review to avoid committing a new
wallet and assert both disarmed setup and uninitialized storage. This scope
neither requires host entropy to be nonempty nor changes the dice derivation.

## Registered execution and independent observers

New file: `unittests/firmware/block13_progress.cpp`, registered unconditionally;
coin and Osmosis cases are behind `#if !BITCOIN_ONLY`. Fixture setup maps private
emulator flash, loads and persists a mnemonic for coin starts, clears workflow
state and resets idle time. Teardown restores flash ownership and storage,
drains confirmation packets, and clears state. This makes near-expiry tests
independent of the order in which other suites ran.

The receive helper encodes protobuf into actual 64-byte USB frames and calls
`usb_test_receive`; it does not call the progress hook. Coin protocol tests use
real initial and continuation handlers; generic Tendermint is the labeled
exception described above. Osmosis amount tests initialize its low-level signer
but send each ACK through USB dispatch. DebugLink choices exercise actual
confirmation loops; queue-drain counts independently show whether an invalid
amount reached review. There is no assertion against an internal idle counter:
observations are signer state, setup state, Failure code, confirmation packet
consumption, storage state and final screensaver state.

Each `Chains/Block13CoinProgress` test below executes once for each of Binance,
Cosmos, Osmosis, Thorchain, Mayachain and TendermintDirectHandler (30 total):

| Registered test stem | Positive/negative contract and observer |
| --- | --- |
| `AcceptedInitialRequestRenewsDeadline` | Start at deadline−1, cross old deadline, signer remains active; GetFeatures/Ping then cannot prevent eventual expiry and signer cleanup |
| `InvalidInitialRequestCannotRenewDeadline` | Zero message count refuses initialization, Failure set, locks at original deadline |
| `AcceptedContinuationsRenewThenPollingExpires` | Two accepted nonfinal messages, each at deadline−1; consume expected review decisions; signer survives each old deadline; polling then expires it |
| `EmptyAndInvalidContinuationsAbortWithoutRenewal` | Missing payload and malformed recipient each refuse before review; queue unchanged, signer aborted, original deadline preserved |
| `DeclinedContinuationCannotRenewAndFreshRetryWorks` | Rejected approval gives ActionCancelled, aborts signer, original deadline expires; a fresh request and accepted continuation then work |

Remaining registered cases:

| Registered case | Contract |
| --- | --- |
| `Block13ResetProgress.InitialRequestRenewsThenPollingExpires` | Real ResetDevice at deadline−1 arms setup; old deadline is renewed, polling does not preserve a stalled ceremony |
| `Block13ResetProgress.EntropyReplyAdvancesOnceIncludingAbsentAndEmpty` | Missing/empty/32-byte ACK reaches backup review once; declining disarms without storage mutation; accepted phase renews; stale ACK cannot renew again |
| `Block13ResetProgress.InvalidInitialRequestDoesNotRenew` | Invalid mnemonic strength fails and original deadline expires |
| `Block13ResetProgress.GenericTendermintWireSurfaceRemainsUnmapped` | Real USB request returns UnexpectedMessage, no generic signer, unchanged deadline (full only) |
| `Block13OsmosisWire.SendAcceptsCanonicalUint64BoundaryAndZero` | 0, 1, max−1 and max pass review/update and renew continuation deadline |
| `Block13OsmosisWire.SendRejectsOverflowAndNoncanonicalBeforeReview` | max+1, a same-length larger value, a longer value, empty, padded, signed, fractional, exponent and spaced strings refuse before review; signer aborts, stale retry rejected, new valid session accepted |
| `Block13OsmosisWire.MissingAmountAndInvalidDenomFailBeforeReview` | Omitted amount, omitted denom, whitespace denom refuse with SyntaxError before review |
| `Block13OsmosisWire.SwapAndPoolAmountsRemainWiderThanUint64` | max+1 survives real swap and LP-add ACK validation, review and signer update, including share/token amount fields |

First full-feature execution: **38/38 passed**, `block13-progress-native.xml`
and `block13-progress-native.log`; the build owner runs subsequent shared builds.
First-run SHA256 receipts:

- XML: `a90cf5fe8eb31a2d8f3b60432551696b76527247febedf59fdf3b47f144a9116`
- Log: `7c3ff926e11583e75e5ec435bcadc001e07c5fc2b11e2f430c982c264054c874`

BTC execution should register the three reset phase tests only. BTC result,
negative-control execution, restored combined run and final artifact identities
must be attached by the shared build owner; they are not inferred from this
full-feature receipt.

## Negative-control plan (not execution claims)

Use backup/restore of only the named source files. Rebuild after each mutation,
run the listed filters, require the specific observer failures below, restore,
then rebuild and run the unmodified focused suite. Do not leave mutations in
an audit checkpoint. Full suite controls may be grouped after the narrow
failure is recorded.

| Mutation | Filter | Required falsification |
| --- | --- | --- |
| Remove the two `note_workflow_progress()` calls in each of the six owned coin headers | `Chains/Block13CoinProgress.AcceptedInitialRequestRenewsDeadline/*:Chains/Block13CoinProgress.AcceptedContinuationsRenewThenPollingExpires/*` | All 12 named cases fail because crossing the prior deadline aborts the active signer. Initial and continuation cases are independent: continuation fixture starts at idle 0 and waits until deadline−1 before its first accepted ACK. |
| Remove only reset's initial hook after `setup_arm` | `Block13ResetProgress.InitialRequestRenewsThenPollingExpires` | Setup is no longer armed after crossing the original deadline; original screensaver appears. |
| Remove only reset's accepted entropy hook after `setup_require` | `Block13ResetProgress.EntropyReplyAdvancesOnceIncludingAbsentAndEmpty` | Accepted ACK still reaches/declines backup, but original deadline locks instead of being renewed. |
| Remove the length/strcmp bound from `osmosis_validate_send_amount`, retaining `osmosis_validate_amount` | `Block13OsmosisWire.SendRejectsOverflowAndNoncanonicalBeforeReview` | Each of the three oversized decimal values reaches review: Failure becomes ActionCancelled from the queued decline rather than SyntaxError, and queue-drain observer falls from 2 to 0. Grammar-negative cases continue to refuse. |
| Add a progress call at entry to each coin continuation handler before validation (optional adversarial placement control) | `Chains/Block13CoinProgress.EmptyAndInvalidContinuationsAbortWithoutRenewal/*:Chains/Block13CoinProgress.DeclinedContinuationCannotRenewAndFreshRetryWorks/*` | Signer still aborts, but the original deadline no longer locks: deadline assertions detect renewing on rejected traffic. |

The above tests prove accepted wait-stage progress and the pre-review send
boundary, not final transaction signatures, every message subtype, or physical
OLED readability. Existing host signature vectors, predecessor coin audits and
physical-device checks remain separate evidence. Final-message handling is
not changed by the continuation hooks.
