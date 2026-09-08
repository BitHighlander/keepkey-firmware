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
