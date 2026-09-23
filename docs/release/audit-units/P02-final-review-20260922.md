# P02 Block 2: final local review handoff (7.15)

Status: ready for final review of the frozen Block 2 behavior. This is a
review handoff, not a new release acceptance receipt or a physical-device signoff.

## Identity and scope

- Current fork audit candidate: `audit/715-scope-repair` at
  `614425a2a14d0113de251e7944118e47f31f5265` (verified against the live
  fork ref on 2026-09-22). This isolated review branch starts at that commit.
- Block 2's original unit sequence is ancestral to the candidate:
  `71ee8c0bc` (tiny credential lifetime), `f20c2497a` (Initialize abort),
  `041a23d5c` (packet lifetime), `5b2a62ce0` (protected Ping response),
  `32c655531` plus `cb5650490` (terminal tiny failure unwind and formatting).
  The original branches still point at these historical unit heads; they have
  not been rebased or force-pushed.
- The canonical product ref `release/7.15` remains at `af979cd509`, diverged
  from this audited candidate. This handoff does not promote or merge it.
- Review the transport receive and dispatch paths, workflow cancellation,
  protected Ping, and their interaction with later session-authority changes.
  Chain-specific signing and release publication are outside this block.

## Behavior and regression evidence

| Contract | Original evidence | Current candidate interaction |
| --- | --- | --- |
| A tiny acknowledgement cannot expose the prior PIN/passphrase buffer | `USBRX.TinyAcknowledgementDoesNotReusePreviousSecret` fails before `71ee8c0bc`, passes after | `lib/board/messages.c` clears decode storage on entry, failure and copy-out; immediate readers clear their copies. |
| Initialize ends all in-flight workflows while retaining the soft-clear PIN policy | `P02-002-initialize-abort.md` records failure on four sessions before the fix and 500 full plus 93 Bitcoin-only native passes after | `fsm_msgInitialize` calls the central `fsm_abort_workflows`; later top-level dispatch and cross-workflow acknowledgement changes also terminate stale authority. |
| Callback packet storage is erased after synchronous consumption | `USBRX.PacketStorageIsWipedAfterCallback` fails before `041a23d5c`, passes after | UDP and USB receive buffers are cleared after callbacks; the device-only callback paths were source reviewed in the original unit. |
| A protected Ping initializes its eventual response after confirmation | `5b2a62ce0` and the recorded host regression | Later `b770928ba` ends stale signing before protected Ping; the current `AutoLockProgress.ProtectedPingCannotSuspendAnOlderSigningSession` test covers that interaction. |
| Terminal tiny receive rejection returns one failure and unwinds the waiting handler | `32c655531` and `cb5650490` | `tiny_handler_rejected` stops the pump, and `reject_tiny_message` suppresses a duplicate reply. |

Later commits touching the same surface were reviewed for scope: `4309ef671`
(rejected transport messages), `0a7e0cf4a` (validated workflow progress),
`b770928ba`, `2bd12230f`, `d4aa26f91`, and `c3ec59c35` (stale signing,
dispatch authority and cross-workflow acknowledgements). These changes preserve
the five Block 2 contracts above and add explicit regression coverage in
`unittests/firmware/fsm.cpp`. The packet-lifetime and tiny-buffer tests remain
registered in `unittests/firmware/usb_rx.cpp`.

The earlier full-diff register also lists F161, F204 and F205 against the USB
regressions. Their Block 2 dispositions are:

| ID | Disposition | Reason and effect on acceptance |
| --- | --- | --- |
| F161 | Accepted limitation | The packet-storage UDP regression is compiled only for the full variant. Bitcoin-only runs the tiny-message regression and its complete native suite. Device USB paths were source reviewed and ARM built. This narrows test coverage but does not block Block 2 review; hardware verification remains a release gate. |
| F204 | Accepted test limitation | A shared UDP port could cause test interference. The test consumes one datagram and restores the FSM callback before assertions; the firmware-equivalent CI run completed. One pass does not prove the test can never be flaky. This does not identify a product defect and does not block Block 2 review; a reproducible port collision would reopen test acceptance. |
| F205 | Refuted | The local `id` is assigned the return value of each synchronous poll before the loop condition is reevaluated. No asynchronous writer changes that local, so a `volatile` qualifier would not strengthen this check. |

## Candidate checks and limits

- [CI run 34951131013](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34951131013)
  passed on the earlier firmware-equivalent head
  `7e091af157131897adc5514de392570c32088946`: full and
  Bitcoin-only ARM builds, emulator builds, native unit suites, host integration,
  Python dylib tests, crypto tests, static analysis, formatting, submodule and
  secret checks, report generation and the CI gate. Emulator publication was
  intentionally skipped.
- `7e091af15..614425a2a` changes only CI workflow files. Firmware code, unit
  tests and dependency pins are identical across that interval. The workflow
  refactor itself is not certified by the earlier run and needs its own release
  gate before whole-product acceptance; it does not change Block 2 behavior.
- Original P02-001 through P02-003 receipts contain the failure-before detail
  and focused native results. They are historical unit receipts, not evidence
  that their old branch heads equal the current candidate.
- Physical USB/OLED and signed-upgrade checks remain release gates. No hardware
  execution is asserted here. The original packet unit source reviewed the
  device callback paths; its native regression exercises UDP storage.

Local review disposition: no known unresolved Block 2 product defect at this
candidate. F161 and F204 are accepted test limitations, and F205 is refuted.
The reviewer should inspect the listed paths and interaction commits against
the stated contracts. New evidence on those paths reopens this receipt under
the rehearsal SOP; unrelated release work stays with its own audit unit.
