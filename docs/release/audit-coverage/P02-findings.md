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

## P02-R02: current outgoing schemas fit packet-tail reads

Reviewed normal/debug transmit loops against generated maximum wire sizes.
The 63-byte packet copies can extend beyond the encoded payload into the
zeroed arena. For every outgoing schema, including inactive/commented map
rows as a conservative superset, maximum payload + 9-byte frame header +
62-byte tail fits the device's 12,301-byte TrezorFrameBuffer.

| Product / assembly | Schemas checked | Largest encoded payload |
| --- | --- | --- |
| 7.14.2 / bae119589 | 60 | CoinTable: 6,060 bytes |
| 7.14.3 / 97f970147 | 60 | CoinTable: 6,060 bytes |
| 7.15 / f20c2497a | 76 | Entropy: 8,195 bytes |

Reproduce with rehearsals/transport_output_bounds.py against each checkout
and its generated build-native/include headers. This is evidence for current
schemas, not a proof for future additions or callback-sized messages. No
current out-of-bounds defect was established; no speculative code fix added.
The complete transport phase remains open.

## Reviewed 7.15 recovery scratch interaction: no new finding

At f20c2497a, attempt_auto_complete() is the sole consumer of
frame_arena_scratch2049(). Its 2,049 uint16_t entries fit the arena; only the
first 2,048 are permuted, retaining the wordlist sentinel at index 2,048.
The overlong-input return precedes acquisition. All three exits after
acquisition wipe the complete scratch table. The permutation/RNG and string
operations do not poll USB or emit messages. Callers use independent word
buffers and do not retain the scratch pointer. A CharacterRequest emitted
before autocomplete finishes transmitting synchronously before acquisition.

Existing Recovery.ExactStrMatch, Recovery.AutoComplete and
Recovery.WordlistLengths pass in the current full native binary. The older
products use a local permutation array, not this shared-scratch mechanism.
This closes the scratch/transport interaction only; recovery state transitions,
word policy, entropy quality and cumulative stack depth remain separate open
audit obligations.

### 7.14.2 ARM result inspected

Run 34291740100's ARM job passed at bae119589956342fdf51914b1c463a1f4dc4acae.
Downloaded artifact 10081622268 (firmware-v7.14.2-bae1195); all 23 file hashes
match arm-build-manifest.json, whose firmware SHA matches the dispatched head.
Application ELF SHA-256 is
6bd596e68ff6c5b468f78b678329aaa967041831eda02eb9939bde8fe8a92808.
ELF _stack minus _ebss is 22,508 bytes, unchanged from the prior measured
reserve. This validates the new pinned-image ARM build; host integration
remains running and canonical promotion remains pending.

## P02-003: lower-level receive packet storage survives consumption

The 7.15 native callback reproduction observes all 64 bytes still present after
UDP dispatch returns. The device main/debug/U2F callbacks also lack cleanup,
including short-read exits. This is residual packet retention, not an established
remote disclosure exploit. Wipe persistent packet storage after consumption.
Reviewed normal decoding, U2F fragment copying and bootloader RAW consumption
for pointer-lifetime compatibility.

[#685](https://github.com/BitHighlander/keepkey-firmware/pull/685), 041a23d5c,
is staged on the frozen Initialize-fix predecessor. The regression fails before
and passes after; all 501 full native and 93 Bitcoin-only tests pass. Device
callbacks require ARM validation. Older-release backports and host/ARM
integration of this new unit are pending. The previously dispatched CI run
34291743075 targets f20c2497a and therefore does not validate this later fix.

### P02-003 older-release backports staged

Both older products reproduce the native packet-retention failure before the
fix and pass afterward. 7.14.2 PR [#686](https://github.com/BitHighlander/keepkey-firmware/pull/686),
head e546d9979, passes all 155 full firmware tests. 7.14.3 PR
[#687](https://github.com/BitHighlander/keepkey-firmware/pull/687), head 47eae604e,
passes all 90 Bitcoin-only firmware tests. Each is based on its frozen
tiny-message-fix predecessor. All three P02-003 units await ARM/host integration;
the earlier running CI jobs do not include these later packet-buffer fixes.

## 7.14.2 canonical assembly advanced after inspected integration

CI 34291740100 completed successfully, including release-evidence-gate.
Verified native artifacts: 154 firmware, 18 board and 4 crypto tests, all passing.
Host artifact: 480 cases, 47 skipped, no failures/errors (433 passing); screenshot
selection: 84 cases, 7 skipped, no failures/errors. Report provenance identifies
bae119589956342fdf51914b1c463a1f4dc4acae; downloaded PDF hash matches its
manifest (29e952b0c8bdce252d602c7c6edc668c260a0c1c836b3efd4655dbb973859098).

Fast-forwarded fork release/7.14.2 from c72672f06 to that exact tested head.
Product PR #650 remains open into unchanged develop da075b8cb. Its description
now identifies the current evidence and explicitly lists pending packet-lifetime
PR #686 and incomplete full-scope audit. The original coverage inventory remains
anchored to its original head; it must be reconciled with accumulated fixes
before final audit closure. No release completeness or Copilot readiness claim.

P02-003 integration dispatched with publish_emulator=false for 7.14.2:
[34292497524](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34292497524),
head e546d99798a5e7dbc54ad5fe43b040a2806c8291, confirmed running. This
validates the later packet-buffer unit separately from the completed earlier
assembly run. Remaining older runs are not restarted merely because they run long.
