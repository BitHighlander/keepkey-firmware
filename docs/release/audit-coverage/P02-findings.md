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

## 7.14.3 canonical assembly advanced after inspected integration

CI 34291741628 completed successfully with both ARM variants, report, evidence
and CI gates; publishing skipped. Downloaded native XMLs show full 189 firmware,
16 board, 18 crypto tests and Bitcoin-only 89/16/18, all passing. Host full has
530 passing/222 skipped cases; Bitcoin-only 303 passing/449 skipped. Screenshot
selection has full 70 passing/14 skipped and Bitcoin-only 28 passing/56 skipped.
No errors/failures. Skip reasons were inspected: four process-owned reboot
cases cannot run in the host container, alongside variant/version exclusions
and other declared applicability limits. These are not counted as passing.

All 23 hashes match each ARM manifest; both identify 97f970147fe23f5cfa95b3575ab8f5874c1ad140.
Full ELF SHA-256 5d01c9e70184a0b8e602d30023754eb7de90695aba8852d5431353fee0ce680a,
reserve 21,312 bytes. Bitcoin-only ELF SHA-256
6403f6923da84f3fd5306130d22d675e291b9ea7d77a3d8cc3c08083e3002339,
reserve 28,268 bytes. Report firmware provenance matches; its PDF hash verifies
as b9261e9348f93edc0d61472c28119482d3cb0a18309a508565fffe05bc61e59c.

Fork release/7.14.3-bitcoin-only fast-forwarded from de0251bbd to 97f970147.
PR #627 remains open into develop; its body now reports this evidence and the
pending packet fix #687. Full audit remains incomplete. Original inventory
head remains the historical inventory anchor until final reconciliation.

Packet-fix integration dispatched separately with publish_emulator=false:
[34292591562](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34292591562),
head 47eae604e183ab1c6c69be7dae43eee60b58326c, confirmed queued.

## Shared-arena declarations and dispatch boundary review

Reviewed the complete messages.h delta for 7.14.2 and 7.15. The older release
removes the two shared-arena declarations alongside the absent arena consumers;
7.15 adds matching TX and scratch declarations. The return types and packed
frame layout agree with their definitions. No actionable header finding.
7.14.3 has no changed messages.h path in its inventory.

Re-read the 7.15 reassembly delta at 041a23d5c: wire IDs are assembled from
two bytes before indexed lookup; map size, stored ID, direction and channel
are checked before selecting a schema. Decoded input capacity is compile-time
asserted per mapped input type in fsm.c. Decode failures, missing handlers and
normal returns clear decoded storage. Tiny input uses a separate arena with
per-type capacity assertions and a 55-byte wire-payload limit. Existing full
and Bitcoin-only builds exercise these compile-time assertions. These checks
do not close message-map product gating or handler-retention review.

## P06 follow-up: stale Ripple host-test skip

The pinned 7.15 host suite unconditionally skips test_sign_with_thorchain_memo
with a claim that RippleSignTx has no memo field. The pinned device protocol
has field 7, generated storage is memo[200], and 7.15's handler reviews the
memo before ripple.c serializes the XRPL Memos array. This skipped test cannot
prove the implementation. Re-enable with appropriate version/product gating
and validate serialization/review in P06; do not count the skip as acceptance.
7.14.3 full-source handler/serializer lacks this memo path, so do not simply
remove the skip across all products. The Bitcoin-only product omits Ripple.

### Ripple memo reproduction on current 7.15

Built kkemu at 041a23d5c, started it with isolated temporary storage and
KK_FORCE_UDP=1, and invoked the original test_sign_with_thorchain_memo method
without its unconditional unittest.skip wrapper. The original signed XRPL
Memos suffix assertion passes (one test, zero skips); no assertion was changed.
Pinned host checkout: 08e491c60fe36110598a3791b2441644fcf55f76.
The process is terminated after the test. Reproduce with rehearsals/ripple_memo.py
and the pinned host dependencies; the harness has a 60-second timeout.

This proves the existing memo serialization case at this head. It does not
close display/cancellation, maximum-length/UTF-8 policy, client API integration
or the host suite's stale unconditional skip. A gated host-test change remains
required; do not claim CI currently executes this case.

### P06-001 host test gate and firmware pin staged

Host fork PR [python-keepkey #76](https://github.com/BitHighlander/python-keepkey/pull/76)
at fb968836ba7ef354c55b89c9ba88bae19bc2c2ce removes the stale unconditional
skip, requires 7.15.0 and preserves the full-feature guard and both original
serialization assertions. All three Ripple tests pass against full kkemu at
041a23d5c; all three correctly skip on Bitcoin-only. Exact host commit fetch
through the configured upstream submodule URL succeeded (publication was to
the fork only).

Firmware fork PR [#688](https://github.com/BitHighlander/keepkey-firmware/pull/688),
7a8a873c3, pins the host fix above frozen packet-lifetime PR #685. Combined CI
is pending. Earlier run 34291743075 at f20c2497a has now passed static analysis
and started downstream builds/host jobs; it does not validate these later units.
Full P06 and release audits remain open.

## P06-002: Ripple display response overwritten by debug capture

Reproduced on full 7.15: show_display returns the known address without
capture but an empty string when screenshot capture requests DebugLinkState
during confirmation. The shared response arena is reused by that handler.
The legacy host display case ignored the response explicitly, masking the bug.

[#689](https://github.com/BitHighlander/keepkey-firmware/pull/689), 885609fbe,
uses the existing local address buffer for confirmation and populates the
response after confirmation. The screenshot regression now passes; all 501
full native tests pass. Rehearsal ripple_display_response.py asserts the known
address and requires captured PNG evidence. DEBUG_LINK-off production failure
was not established. Older releases, persistent host assertion and integration
remain pending. This is a bounded fix, not completion of the Ripple audit.

### P06-003 permanent display regression staged

Host PR [#77](https://github.com/BitHighlander/python-keepkey/pull/77),
81b950da16209c492a956bb4969db93963e01c4f, strengthens the existing
screenshot-selected address test with the known response assertion on 7.15.
All three Ripple address tests pass with capture enabled against 885609fbe.
The exact host commit is fetchable through the configured submodule URL.
Firmware PR [#690](https://github.com/BitHighlander/keepkey-firmware/pull/690),
cecf1ea20, pins it above the frozen response fix. Combined CI remains pending.

7.14.2 packet-buffer run 34292497524 completed successfully; artifact inspection
and canonical advancement remain pending. Its native/host/report artifacts are
10082076305 / 10082076607 / 10082087463; ARM is 10081905002.

## 7.14.2 packet-lifetime integration accepted into canonical branch

Run 34292497524 succeeded. Inspected downloaded artifacts: firmware 155, board
18 and crypto 4 tests all pass; host 433 pass/47 skip and screenshot selection
77 pass/7 skip, zero failures/errors. Both report and ARM manifests identify
e546d99798a5e7dbc54ad5fe43b040a2806c8291; all 23 ARM hashes verify.
Application ELF SHA-256:
88eaaaa336b1965a2c101f3b8da77b138e63788f6b64aee32dcc120c2ae0bcec.
Reserve remains 22,508 bytes. Report PDF hash verifies as
e3d8cad46c87bac96c6d1c842257b6fb1826353f826dfcdbd0c03bc28a900f9e.

Fast-forwarded canonical release/7.14.2 from bae119589 to e546d9979. Product
PR #650 remains open into fork develop; its current evidence and pending audit
wording were updated. P02-003 is integrated for this product. Full release and
older-release Ripple display review remain open; no Copilot readiness claim.

### P06-002 reproduced and fixed on 7.14.2

Using the release's own pinned host suite and current rebuilt kkemu, the
screenshot rehearsal returns an empty address before the fix and the expected
known address after it. All 155 native firmware tests pass.
[#691](https://github.com/BitHighlander/keepkey-firmware/pull/691), 71617e991,
keeps the address in a local MAX_ADDR_SIZE buffer and fills the response after
confirmation, above frozen packet-lifetime head e546d9979. No DEBUG_LINK-off
production failure claim. Permanent older-host assertion and ARM/host integration
remain pending. 7.14.3 full-variant reproduction remains pending; its Bitcoin-only
product does not expose Ripple.

### P06-002 full 7.14.3 backport verified and staged

Built full variant separately in build-native-full using the existing native
compiler/nanopb settings with KK_BITCOIN_ONLY=OFF. Its own pinned host suite
reproduces the empty displayed address with screenshot capture. The same local
address/late-response fix passes that regression, all 190 full native tests
and all 90 Bitcoin-only native tests. Bitcoin-only does not expose Ripple.
[#692](https://github.com/BitHighlander/keepkey-firmware/pull/692), 1ce4d3961,
is staged above frozen packet-lifetime head 47eae604e. Permanent older-host
assertion and combined integration remain pending.

The earlier packet-lifetime CI 34292591562 has completed successfully, including
both ARM variants and evidence gate. Artifact inspection remains pending before
canonical advancement; that earlier run excludes the Ripple fix.

## 7.14.3 packet-lifetime assembly accepted into canonical branch

Inspected successful CI 34292591562 artifacts. Native firmware full 190 /
Bitcoin-only 90, with 16 board and 18 crypto in each, all pass. Host full
530 pass/222 skip; Bitcoin-only 303 pass/449 skip. Screenshot selection full
70 pass/14 skip; Bitcoin-only 28 pass/56 skip. Zero failures/errors.
Both ARM manifests and report identify 47eae604e183ab1c6c69be7dae43eee60b58326c.
All 23 hashes per ARM variant verify. Full ELF SHA-256
b29cba5b78a8e44fc2fc253cd5a2a2a9246a48b34539f3cae92b9f8e5548b783,
reserve 21,312 bytes; Bitcoin-only ELF SHA-256
66c1e2cec79dc040b459b3e1f8b88fe6f1a97498c0e44df7af0cc0b674839240,
reserve 28,268 bytes. Report PDF verifies as
0dd42ea9c03c293de0b749362bf7375e011e3b6954b27e1b8cc2a1986f1054c2.

Canonical release/7.14.3-bitcoin-only fast-forwarded from 97f970147 to 47eae604e;
PR #627 stays open into develop. Its body now records current evidence and
pending Ripple PR #692 plus incomplete audit/older-host assertion. No
full-release acceptance or Copilot readiness claim.

## Ripple integration and older host assertions

Dispatched publish_emulator=false CI for 7.14.2 Ripple head 71617e991:
34293561568; 7.14.3 head 1ce4d3961: 34293563979; 7.15 combined packet/Ripple/host
head cecf1ea20: 34293571582. All were confirmed queued. Older 7.15 run
34291743075 continues separately and excludes these later units.

Permanent older-host assertions staged in python-keepkey fork PRs
[#78](https://github.com/BitHighlander/python-keepkey/pull/78) at
c9182c9b6ed11f0d5db054b81d3da2e65b245536 and
[#79](https://github.com/BitHighlander/python-keepkey/pull/79) at
8e5eaaaa10787a64f5d54780bb2b5f72d3d82700. Each full release passes all three
address tests with capture enabled. Firmware pin updates remain pending; the
newly dispatched older-release runs do not yet execute these assertions.

Found 20 active P00 documentation PR CI runs; requested cancellation of 19
superseded runs, retaining newest 34293553287. First follow-up confirmed three
terminal cancellations; others were still processing cancellation. Recheck
until terminal. Added SOP batching and superseded-documentation cancellation
rule. This overhead was caused by frequent ledger pushes, not release testing.

### Older permanent host assertions pinned; redundant CI cancellation complete

7.14.2 firmware PR [#694](https://github.com/BitHighlander/keepkey-firmware/pull/694),
bedf3aca1, pins host c9182c9b6ed11f0d5db054b81d3da2e65b245536 above 71617e991.
7.14.3 PR [#693](https://github.com/BitHighlander/keepkey-firmware/pull/693),
0292e7fa2, pins host 8e5eaaaa10787a64f5d54780bb2b5f72d3d82700 above 1ce4d3961.
Both exact host commits fetch through the configured submodule URL. Previous
full-emulator screenshot runs passed all three address tests per release.
Combined validation of these later pins remains pending; earlier dispatched
Ripple runs cover their firmware predecessors.

Re-polled the P00 runs: all 19 superseded runs are now terminal cancelled.
Only retained newest 34293553287 remains active. Six lagged the initial cancel
requests; force-cancel accepted one, while five had already completed by that
request. Final list confirms all nineteen cancelled. Release runs were not
cancelled. Ledger updates are batched locally to avoid recreating that queue.

## P06-004: incorrect 192-byte Ripple memo prefix

The native boundary test reproduces two prefix bytes at length 192 instead of
one. XRPL's documented single-byte range includes 192:
https://xrpl.org/docs/references/protocol/binary-format#length-prefixing
7.15 memo[200] permits this input. Change `< 192` to `<= 192`. Vectors at
191/192/193/199 now pass, as do all 502 full native firmware tests.
[#695](https://github.com/BitHighlander/keepkey-firmware/pull/695), 39503dacf,
is staged above the frozen display-test pin. Older serializers lack memo
implementation and use shorter fixed lengths; no old-product trigger has
been established. Full serialization/helper-domain and integration review
remain pending.

Earlier 7.15 CI 34291743075 completed successfully at f20c2497a. Its artifact
inspection and canonical advancement remain pending; it excludes subsequent
packet/Ripple units. New combined run 34293571582 targets cecf1ea20 and also
excludes this newest length-prefix fix.

## 7.15 earlier audited assembly verified and canonical advanced

CI 34291743075 succeeded at f20c2497a0990a6690c5bb804414c11cac74bf58.
Inspected native XMLs: 500 full / 93 Bitcoin-only firmware, 13 board and 18
crypto per variant, 6 full Pallas tests, all passing. Host full 719 pass/36 skip;
Bitcoin-only 307 pass/448 skip. Screenshot full 171 pass/12 skip; Bitcoin-only
35 pass/148 skip. All 23 hashes per ARM manifest verify against that head.
Full ELF 50d412ad2b54fa88142400aaf7b2a3e2194983d5d8090b80c7b878fc13a471bd,
reserve 16,392 bytes; Bitcoin-only ELF
4f0ae2af548dd00a0633ef29a6f063855d33772342812d42b9b23ee18dbfb07f,
reserve 31,424 bytes. PDF text identifies the exact candidate; its computed
SHA-256 is 84501e10c70c22ee377f4f5a0bce6aa931af9ed4365ebf2d3df67e58517fb876.
This workflow uploads only the PDF, with no separate report hash manifest.

Canonical release/7.15 fast-forwarded from a18317f88 to f20c2497a. PR #629
remains open into fork develop and now lists these results plus pending later
packet/Ripple units. This accepts the tested assembly only; complete audit and
Copilot readiness remain unproven. Batched ledger/SOP updates are published
with this canonical advancement.

## P06 bounded Ripple serializer review

At 39503dacf, traced all production callers of ripple_serializeVarint and
ripple_serialize: only ripple_signTx drives transaction serialization; its
caller is the guarded Ripple handler. Current variable lengths are classic
account payload 20, public key 33, DER signature bounded conservatively by its
75-byte destination, and 7.15 memo at most 199 bytes. Thus the three-byte length
branch and its upper-limit boundary are not reachable from shipped handlers.
The 192-byte case is reachable and fixed separately in P06-004.

Conservative maximum signed output is 404 bytes: type 3, flags 5, sequence 5,
destination tag 5, last-ledger sequence 6, amount 9, fee 9, public key 35,
signature 77, source/destination 22 each, memo 206. This fits the 1,024-byte
serialized payload. The signed pass uses sizeof(serialized_tx), which includes
the size member, but that overly broad end pointer is not reached by current
inputs. No current buffer overflow established from it; retain this boundary
obligation if schemas/callers expand. Older products lack memo serialization
and have a smaller bound.

The handler checks payment presence, destination length/checksum/version, fee
range, amount limit and render success before confirmation, and refuses sign
failure. Reviewed changed status propagation through the serializer and handler.
Remaining obligations include transaction-flag semantics, complete memo display
and cancellation coverage, and old-product handling of protocol fields they do
not implement. This is not complete Ripple acceptance.

## P06-005: full 7.14.3 silently omitted a supplied Ripple memo

Unwrapped the original host memo test on full 7.14.3: the call returned a signed
transaction, but the unchanged memo-suffix assertion failed. Protocol memo
storage exists; this serializer does not implement it.
[#696](https://github.com/BitHighlander/keepkey-firmware/pull/696), 06d84f561,
rejects nonempty memos before PIN/key derivation. Rejection, ordinary signing
and fee host tests pass, as do all 190 full native tests. Bitcoin-only compiles
with this handler excluded. Rehearsal ripple_unsupported_memo.py is repeatable
against the full build. Permanent host CI coverage and integration remain open.
7.14.2's pinned schema has no memo member; no blind backport was made there.

### P06-006 permanent unsupported-memo test pinned

Host PR [#80](https://github.com/BitHighlander/python-keepkey/pull/80),
0f4c839db56767eac43c9c7be8a2e2b589667b49, requires explicit syntax rejection
for nonempty memos on full 7.14.3, gating older/BTC/7.15 products appropriately.
The rejection and ordinary signing/fee tests pass against 06d84f561. Exact
commit fetch through the configured URL succeeds. Firmware PR
[#697](https://github.com/BitHighlander/keepkey-firmware/pull/697), 89c03a5a1,
pins this host test above the frozen rejection fix. Combined CI remains pending.
