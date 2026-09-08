# P02 transport, dispatch and message lifetime

Status: in progress. No complete-phase claim.

## P02-001: Tiny-message credential lifetime

Confirmed on all three releases: a PassphraseAck followed by an empty ButtonAck
returns the previous passphrase bytes in the second decoded caller buffer.
Ordinary dispatch cleanup did not cover the tiny-message arena. Fixed shared
storage and temporary decoder-copy lifetime, plus immediate PIN/passphrase and
confirmation caller exits. The dice caller already clears its buffer at exit.

| Product | Unit PR | Head | Native validation |
| --- | --- | --- | --- |
| 7.14.2 | [#681](https://github.com/BitHighlander/keepkey-firmware/pull/681) | `bae119589` | 154 full-firmware tests |
| 7.14.3 | [#682](https://github.com/BitHighlander/keepkey-firmware/pull/682) | `97f970147` | 89 Bitcoin-only firmware tests |
| 7.15 | [#683](https://github.com/BitHighlander/keepkey-firmware/pull/683) | `71ee8c0bc` | 499 full and 93 Bitcoin-only firmware tests |

Each product's new native UDP regression fails before and passes after the fix.
Existing USB overflow, error handling and nanopb bounds tests pass. See unit
receipt P02-001-tiny-lifetime.md on each branch for exact native limitations.
Full ARM/host integration and the complete P02 audit remain pending.

## Reviewed decoder delta: no new finding

All three products have the identical pb_decode.c blob
`dbb90ad7e40cc1a2431899eb1a17a3e10571fe84`. Reviewed the changed static-bytes
capacity check and surrounding varint, allocation-size overflow, destination
size and read handling. The 7.14.2 comparison additionally contains formatting
and comment differences only. The schema capacity remains separate from the
aligned repeated-element stride. Checked include/pb.h's member-array capacity
macros and generated descriptor use. All four native runs above pass the three
NanopbBounds cases: exact 73-byte maximum accepted, padding byte 74 refused,
capacity distinct from structure stride. This disposition covers the changed
decoder hunks and their descriptor interaction, not every unchanged nanopb path.

## Remaining reviewed-path interactions

Shared RX/TX arena acquisition resets partial reassembly; TX loops do not call
usbPoll while emitting. Complete scratch-consumer, lower-level packet lifetime,
message-map product gating, handler retention and cancellation/revocation paths
remain open. Do not infer their completion from the tiny-buffer fix.

## P02-002: 7.15 Initialize retained signing sessions

The native Initialize regression leaves Binance, Osmosis, THORChain and
MAYAChain initialized before the fix. 7.15 had retained a partial abort list;
its soft session clear deliberately does not terminate all signing state.
7.14.2/7.14.3 already use fsm_abort_workflows() at this boundary. Restore that
call for 7.15, preserving session_clear(false) and therefore cached PIN.

[#684](https://github.com/BitHighlander/keepkey-firmware/pull/684),
`f20c2497a0990a6690c5bb804414c11cac74bf58`: all 500 full-firmware and 93
Bitcoin-only firmware tests pass. The low-level soft-clear preservation test
still passes separately. Removed one byte-identical duplicate ceremony macro
in the reviewed FSM source; this cleanup does not alter preprocessing behavior.

## P02-R01: legacy structured EIP-712 state is not a shipped path

A suspected stale local domain-hash cache in e712_types_values() is unreachable
through the current handler: ethereum_structured_eip712_enabled() returns false
before key derivation or that implementation. The existing native capability
test pins the disabled state. Do not add a current release blocker or silently
re-enable the feature. Re-enablement needs its own P05 state/display review.

## Accumulated-head integration validation

Runs were explicitly dispatched with publish_emulator=false; no release tag,
publication or develop merge. Canonical branches remain unchanged until these
results are inspected. Green integration will not complete the remaining audit.

| Product | Audited-unit assembly head | CI run | Status at dispatch |
| --- | --- | --- | --- |
| 7.14.2 | `bae119589956342fdf51914b1c463a1f4dc4acae` | [34291740100](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34291740100) | Running |
| 7.14.3 | `97f970147fe23f5cfa95b3575ab8f5874c1ad140` | [34291741628](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34291741628) | Running |
| 7.15 | `f20c2497a0990a6690c5bb804414c11cac74bf58` | [34291743075](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34291743075) | Queued |
