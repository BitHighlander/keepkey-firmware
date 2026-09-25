# Handoff: ERC-7730 embedded calldata (Phase E): goals, needs, hard requirements

Date: 2026-09-25. Status: **E1 and E2 implemented in block 7b; 7.16 decisions remain.** Blocks 7a (#837) and 7b (#863) are the base. Phase 0–D status is in `HANDOFF-ERC7730-715-FORMATTERS.md`.

This document replaces the earlier "three options" summary (lower the SRAM floor, redesign memory, or defer). Those options followed from an assumption nobody had required: that the outer and inner programs must be resident at the same time. Section 3 questions that assumption and the others behind the earlier ">2 KB" estimate.

The method is the five-step order:

1. Question each requirement and name who owns it.
2. Delete parts.
3. Simplify what remains.
4. Shorten the test loop.
5. Automate.

## 1. The goal, stated as the user's need

A user is about to sign a transaction whose calldata carries **another call inside it**: a Safe `execTransaction`, a `multicall`, `permitAndCall`, a batch executor. The outer call means little on its own ("execute a transaction"). The risk and the intent are in the inner call.

The user needs to know, from the device alone and before signing:

1. **Where** the inner call goes: the callee address.
2. **What** it does: the inner function and its arguments, clear-signed if a definition exists.
3. **What rides with it:** any value it moves (`amountPath`), and on whose behalf it acts (`spenderPath`).
4. **How** it executes, where the outer protocol says so. For example, Safe's `operation` distinguishes CALL from DELEGATECALL, and a delegatecall runs the inner code as the Safe itself.

Everything shown must be taken from the bytes being signed.

## 2. Measured scope (pinned registry `9f37816a`)

- 32 embedded-calldata fields across 22 descriptors. By protocol:
  - Safe `execTransaction`, `setup` and the proxy factories: 18.
  - Morpho bundler.
  - 1inch.
  - Positions/Orders, ve33 and VeToken, lpv3.
  - Kiln, EthVault, BatchExecutor.
- By function: `execTransaction`, `setup`, `createProxyWithNonce[L2]`, `createProxyWithCallback`, `multicall`, `batchExecute`, `permitAndCall`, `reenter`, `createSplitterAndCall`.
- Parameters used:

  | Parameters | Fields |
  |---|---|
  | `calleePath` only | 22 |
  | `calleePath` + `amountPath` | 4 |
  | `calleePath` + `amountPath` + `spenderPath` | 6 |

  `chainIdPath` and `selectorPath` do not appear.
- Phase A–D blocks 32 of the formats, one per embedded field (measured: removing only kind 13 from the mirror moves the signable count from 1,326 to 1,294). Of the remaining unsignable formats, about 130 are refused on purpose: slices, packed words, nested arrays, ABIs deeper than 8.
- **Not yet measured:**
  - how long the inner calldata really is (a Safe `setup` can be long);
  - how many inner calls have a registry definition of their own;
  - how many of these flows reach the device as EIP-712 rather than calldata. Safe owners usually sign the `SafeTx` typed hash, whose `data` field is the same embedded call.

## 3. Premises to question

Each item names what we assumed, who actually requires it, and what changes if it goes. The owner must decide the ones marked **decision**.

| # | Premise we carried | Who requires it | If deleted or changed |
|---|---|---|---|
| P1 | The outer and inner programs must be loaded at the same time. | Nobody. It is an implementation habit. | The device already re-streams the definition for every selection and replays the calldata for every capture. Inner and outer can take turns in the same memory. What must survive a switch is a small **resident set**, not a second copy of each structure. |
| P2 | The inner calldata must be captured on the device (captures are ≤128 B). | Nobody. | The inner bytes can be **streamed and hashed** by the outer pass. The host then re-sends them as their own stream, and the device checks the hash. There is no length limit beyond the existing stream limits. |
| P3 | A second preload slot and verifier are needed. | Only concurrency (P1). | Verification is streaming and transient. What persists is an accepted identity of about 200 B, not a verifier of 952 B. |
| P4 | The inner definition must be preloaded before signing starts. | Nobody. | The device already requests definition chunks by (kind, chain, contract, selector) during signing (`EthereumClearSignDefinitionRequest`). An on-demand inner request may need no new message, or only a depth/role marker. **Decision:** is a protocol change acceptable, and on which canonical branch? |
| P5 | The inner call must be fully clear-signed, or the format is refused. | **Decision.** | The alternative is a minimum viable inner review: callee (EIP-55), selector, value and operation, with the inner bytes shown by hash or as raw data under a device-owned "not clear-signed" label. That would make every one of the 32 fields signable without any inner definition, and clear-signing becomes an upgrade. |
| P6 | Recursion to any depth. | ERC-7730 allows it; no registry format in scope needs it. | Cap at one level. A deeper call is refused at preload, or shown by the P5 minimum. |
| P7 | `multicall` must be supported in the first cut. | Registry (Morpho and others). | `multicall(bytes[])` is Phase D iteration over embedded calls. It can come later than single embedded calls. **Decision:** the order. |
| P8 | Embedded calldata in EIP-712 (Safe `SafeTx.data`). | Possibly the largest real-world use; not yet counted (§2). | **Decision:** in or out of the first cut. Typed data currently refuses iteration and containers. |
| P9 | The device must find the inner definition. | Nobody. | Discovery is a host job (§4). The device only checks that what it is given is bound to the signed bytes. |
| P10 | The 256 B single-change SRAM review rule applies as usual. | Owner rule. | Unchanged. The design must state its resident set in bytes, measured, before any code is written (H9). |

## 4. What the host can do, and what the device must do

The host is untrusted but useful. The rule: the host may **find, fetch, split and send**, but every fact the user relies on is checked on the device against the signed bytes.

| Work | Host | Device |
|---|---|---|
| Find the inner definition in the catalog | yes | — |
| Extract the inner bytes from the outer calldata | yes (sends them as a stream) | checks them against the outer pass (hash, length, position) |
| Tell the device the callee, selector or value | may hint | **derives each from the signed bytes**; a hint is never trusted |
| Stream the inner definition envelope | yes | authenticates it: signature, delegate, epoch, capability table |
| Bind the inner definition to the call | — | chain = outer chain; contract = the callee from the outer calldata; selector = the first 4 inner bytes |
| Split `multicall` elements | yes | binds each element to its index in the signed array |
| Render any text | never | always, device-owned and escaped |
| Decide that a call is "safe" | never | never. The device shows; the user decides. |

## 5. What can be streamed

Every large object already has a streaming path. The requirement is that no large object has to be resident twice.

- **Outer calldata:** replayed per pass, as now.
- **Inner bytes:** streamed inside the outer pass, where a running hash is taken (no capture), and re-streamed by the host as the inner calldata for inner passes.
- **Definitions:** streamed per selection, as now. Outer and inner alternate.
- **Inner ABI stream:** the same stream structure, reset per pass. It never coexists with an outer pass.

## 6. Hard requirements

These are non-negotiable. H1–H7 carry over from Phases 0–D; H8–H16 are specific to Phase E.

- **H1 Additive only.** The ordinary review, the forced data-hash confirmation and the final signing screen stay.
- **H2 One value tree.** Every value shown comes from the bytes that are signed. Every pass is hash-committed and matches the first.
- **H3 No refusal mid-review because of a program's shape.** Anything the runtime cannot execute is refused before the first screen. Data-dependent faults (malformed calldata) are caught by the up-front validation pass wherever possible.
- **H4 Injective text** through `erc7730_format_text()`. Device-owned titles; numbered parts.
- **H5 Trust labelling.** A runtime signer is "NOT verified by KeepKey". Signer text sits beside the raw value. Asset facts come only from firmware tables.
- **H6 Fail closed.** Any failure aborts before a signature and clears the preload.
- **H7 No flash writes; AdvancedMode required;** the preload lifetime is unchanged.
- **H8 Binding.** An inner definition is used only when its chain equals the outer chain, its contract equals the callee read from the signed outer calldata, and its selector equals the first 4 bytes of the signed inner bytes.
- **H9 Resident-set budget.** The design lists every byte that persists across the outer↔inner switch, measured on ARM. The total must fall under the review threshold, or come to the owner with the number.
- **H10 Byte identity.** Inner bytes the host re-streams must equal the embedded bytes of the signed outer calldata: digest, length and position. Otherwise it is refused before any inner screen.
- **H11 Depth bound.** One level unless the owner decides otherwise. Anything deeper is handled per the decision on P5/P6, never by partial display.
- **H12 Execution context is shown** when the outer protocol defines it: Safe `operation` (CALL or DELEGATECALL), `amountPath` (value, using the firmware native asset), `spenderPath` (whose authority).
- **H13 No inner definition does not mean no review.** What the user sees when the host has no inner definition is an explicit owner decision (P5). It is never a silent blind sign and never a silent refusal.
- **H14 Same capability discipline.** The inner program passes the same preload capability table. The python-keepkey mirror stays in lockstep. The registry signable count is asserted.
- **H15 Stack.** The deepest new chain is measured against the reserve. No new frame exceeds the existing ERC-7730 display frames without review.
- **H16 Typed data parity.** If P8 is in scope, the same bindings hold for `SafeTx.data`.

## 7. Parts to try to delete first (step 2)

Each goes unless a named requirement brings it back:

- recursion beyond one level (P6);
- `multicall` in the first cut (P7);
- a new protocol message, if the existing request plus a marker is enough (P4);
- inner capture buffers (P2);
- a second verifier or loader instance (P1, P3);
- `spenderPath` as a separate formatter: it may be an addressName field.

The target is to add back at most ~10% of what was deleted.

## 8. Evidence each design proposal must bring (steps 4–5)

- The measured resident set (H9) and deepest stack chain (H15).
- The registry signable count before and after, from the lockstep test.
- Adversarial wire tests with exact text:
  1. The host substitutes different inner bytes.
  2. The host sends an inner definition for another callee.
  3. The host sends an inner definition for another selector or chain.
  4. The inner bytes are truncated or padded.
  5. A DELEGATECALL is shown as such.
  6. No inner definition exists (P5 behaviour).
  7. Depth 2 is attempted.
- A negative control for each new check, plus OLED screenshots per the gate-3 rule.
- The full CI graph green on the exact head. Local runs in the `kk837-dev` image (CI's base image) are the fast loop.
- The §2 measurements that are still missing.

## 9a. Owner decision (2026-09-25): no clear-sign means blind sign in 7.15, and rejection in 7.16

- **7.15:** the whole ERC-7730 runtime already sits behind AdvancedMode and shows "NOT verified by KeepKey". It is not clear-signing in the 7.16 sense. An inner call the device cannot clear-sign may therefore be shown under a **blind-sign warning**, with AdvancedMode on, which the runtime already requires.
- **7.16:** AdvancedMode becomes a **hard gate**. Anything that cannot be clear-signed must be **rejected**, with no blind-sign fallback. This applies to inner calls, and to every refusal class in the formatter plan: slices, packed words, missing definitions.

## 9b. Owner decisions (2026-09-25) and status

- A "no definition" reply is allowed. Build order: E1, the 7.15 blind-sign path, then E2, inner clear-signing, then `multicall` and Safe typed data.
- **E1 is implemented (block 7b).**
  - Formatter kind 13 runs for calldata definitions. Its roles are 1 (the inner bytes), 15 (callee), 17 (value) and 18 (authority); python-keepkey now emits 17 and 18 from `amountPath` and `spenderPath`.
  - The inner bytes are located, not copied: a new ABI-stream locate mode keeps only the first four bytes, the length and the payload offset, so an inner call of any length works.
  - Display: a "Blind signature: The inner call is not clear-signed" screen, then the field with the callee, `Function 0x<selector>`, `Data N bytes` (or `No data`), `Value <native>` and `As <address>`.
  - The code carries the 7.16 note: reject there instead.
  - Registry: 1,326 signable. SRAM reserve 18,000 B (−48 B).

- **E2 is implemented (block 7b).** The inner call is clear-signed with its own definition, one level deep.
  1. At the embedded field, after the outer signer and intent screens, the device requests the inner definition by (calldata, chain, callee, selector, `recursion_depth=1`). The request carries only facts it read from the signed calldata, and the reply streams into the preload slot.
  2. An empty chunk (offset 0, `total_length` 0) means "none", and the E1 blind path follows. python-keepkey's `Catalog.chunk` sends it for an unknown nested lookup.
  3. Before any inner screen, the device checks the binding (H8). It then shows the call's context (callee, selector, length, value, authority) and runs the inner program titled "Inner signer", "Inner action", "Inner field", and "Inner text i of n" / "Inner value i of n" for interpolated intent parts.
  4. Inside it, `@.to`/`@.value`/`@.from` mean the callee, the value moved and the spender (the outer contract if unnamed). When the outer formatter names no `amountPath`, the calldata does not say what the inner call moves: an inner definition that shows `@.value` is then refused before any inner screen and the call is shown blind (the verifier records `reads_value`; `erc7730_workflow_fetch_feed` checks it).
  5. Every inner pass, including the inner validation pass, replays the whole outer calldata, hashes it against the reviewed digest and feeds only the located inner arguments to the ABI stream.
  6. At the inner end the device re-fetches the outer definition by its id, re-authenticates it and resumes after the instruction that held the inner call.
- **Not clear-signed (blind in 7.15):**
  - an inner call inside an iteration (multicall: E3);
  - a call at depth 2;
  - inner bytes without a selector, or not whole ABI words.
- Resident set, measured on ARM: the workflow grew 3,424 → 3,608 B over E1 and E2. SRAM reserve 18,000 → 17,864 B for E2 (−136 B). The deepest frame is still the definition-chunk handler (2,344 B).
- Wire tests (exact text):
  - `test_inner_call_is_clear_signed_with_its_own_definition` (the outer field after the inner call proves the resume);
  - `test_inner_call_without_a_definition_is_blind_in_715`;
  - `test_inner_definition_for_another_call_is_refused` (a hostile host substitutes the selector);
  - `test_inner_bytes_changed_in_an_inner_pass_are_refused` (refused on pass 5, before any inner field).
- Negative controls: removing the binding, feeding the whole outer calldata to the inner stream, or reading inner containers from the outer transaction each fail the matching test.
- Found while testing: the dispatcher's stale-continuation guard (`fsm.c`) had to accept definition chunks in the new FETCH phase. A replay must reset the pending selection kind, or the first inner replay is taken for the outer program's last path selection.

## 9c. Audit remediation (2026-09-25)

An adversarial audit of the 7b diff (102 agents) confirmed 42 findings, clustered into D1–D19; none was P1. Fixed:

- **Mid-review failures the preload now refuses or the runtime now handles:** numeric constants as values (D1: first widened to words; after the re-audit, refused at preload for every formatter but raw, and for an embedded call's callee, value and authority, because a constant rendered as an amount looks decoded. The official registry uses none); an embedded call as an intent part (D2); signer text over 64 bytes and unit decimals over 77 (D3); a literal callee (D9); control characters, which are escaped as `\xNN` (D8); a raw value over the 128-byte capture, shown blind with "Not shown: N bytes" (D8). In typed data the walk has already shown the value in full, so there it reads "Shown above in full: N bytes", with no blind warning; an inner definition the device refuses (bad program, unknown signer), shown blind instead of aborting (D17); an inner definition that shows `@.value` with no `amountPath` (critic gap, above).
- **Wrong source for a fact:** a Wanchain transaction type leaking into a native amount (D4); a signer's native alias overriding the firmware token table (D5).
- **Presentation:** distinct titles "Intent text i of n", "Intent value i of n" and "Signer field i of N", so a signer fragment cannot pass for a device-rendered value (D6/D14); a value too long for one confirmation splits into numbered confirmations between lines (D7). This does not keep an address on one OLED page: the board pager wraps each confirmation by pixel width, so an address or long number can continue on the next page of the same confirmation, which must also be confirmed; a unit's base, a threshold message and an enum label are marked as the signer's, the mark coming before the value so it is never on a later page, and a unit always shows the raw integer (D16).
- **Beyond ERC-7730:** D8's escaping also runs in the ordinary streamed EIP-712 review (`render_part`). A typed-data string with a control character used to abort signing there; it now shows as `\xNN` and can be signed.
- **Callee sources:** the callee comes from calldata or a transaction container (`@.to`, or `@.from`, the device-derived signer), never from a signer constant.
- **Mirror:** the python-keepkey table limits match the device's (D11). A root path is handled (D12). Wire tests filter pager continuation pages instead of de-duplicating (D15).

Documented, not changed. The first three fail closed, with no signature:

- **D10, parallel arrays.** Inside an iteration only the value argument must walk the iterated array; any other `[]` path (a token, a collection, a callee) is paired with it by index, as ERC-7730 pairs arrays. If that array is shorter, the capture fails mid-review with "calldata does not match definition". If it is longer, its extra elements are not shown. Test: `test_parallel_arrays_pair_by_index_and_a_short_one_fails_closed`.
- **D18, fixed indices into dynamic arrays.** Preload cannot know a dynamic array's length, so `path.[0]` over an empty array fails mid-review with the same message. Test: `test_a_fixed_index_into_a_short_array_fails_closed`.
- **The inner validation pass runs after the outer screens.** Inner bytes that are not canonical for the inner ABI (trailing words, non-minimal offsets) abort with "calldata does not match definition" instead of taking the blind path.

These sign, and are recorded as limits:

- **Typed data repeats leaf reviews.** Each captured typed-data field replays the whole typed data, and every leaf is confirmed on each walk. The first message walk is also the first field's capture, so N captured fields cost N complete leaf reviews (at least one). The UX cost is not measured.
- **DELEGATECALL is not tied to the inner review (owner decision for 7.16).** The Safe `operation` word is shown only as the outer descriptor's own field. An inner definition is clear-signed the same way under `operation = 1`, where the callee runs against the Safe's storage. §8 item 5 has no code path. In 7.15 the outer review shows the operation value; 7.16 must decide whether a DELEGATECALL inner call is rejected.
- **Hidden fields.** The compiler omits every field the descriptor marks `visible: "never"` (for example Safe's `safeTxGas` and `signatures`). Those fields are not in the signed program, so the device cannot know they exist. The device hides nothing it is given.

New wire tests: `test_only_a_raw_field_shows_a_signer_constant`, `test_a_long_typed_data_value_points_to_the_walk_not_blind`, `test_declining_any_certified_screen_returns_no_signature`, `test_a_wanchain_transaction_is_never_certified`, `test_control_characters_in_a_value_are_escaped`, `test_a_raw_value_too_long_to_capture_is_shown_blind`, `test_multiline_values_split_between_lines`, `test_an_inner_definition_the_device_refuses_falls_back_to_blind`, `test_inner_definition_for_another_callee_or_chain_is_refused`, `test_inner_calls_read_their_own_containers`, `test_a_call_at_depth_two_is_shown_blind` (asserts no request deeper than depth 1), `test_embedded_calls_inside_an_iteration_are_shown_blind`, `test_an_inner_value_the_calldata_does_not_carry_is_never_shown`, plus the two fail-closed tests above. Every test that signs first signs the same transaction on the ordinary path and requires an identical signature. Negative controls: reverting each of 15 checks on its own fails its named wire or unit test. The callee/chain binding is checked twice (header screen and `erc7730_workflow_fetch_complete`), so its control removes both.

**Where the tests live.** The Phase 0–E runtime tests (38) moved from `scripts/emulator/test_stack07_regressions.py` to python-keepkey `tests/test_msg_ethereum_erc7730_runtime.py`. Only pyk tests get OLED captures in the release PDF. They are rows EX1–EX38 of report section EX (7.15.0+), and the module is in `MUST_RUN_MODULES` from 7.15.0 (full product only): a skip there fails the report. The firmware file keeps the 7a contracts and imports the harness (`Erc7730Harness`) from the pyk module. Captures cover the screens the definition adds; the ordinary review that follows is not captured, since the identical signature proves it unchanged.

## 10. Remaining 7.16 work

- Apply the hard gate from §9a: reject calls the device cannot clear-sign.
- Decide whether to reject DELEGATECALL inner calls, whose execution context is currently shown only by the outer descriptor.
- Scope `multicall` iteration and EIP-712 `SafeTx.data` for a later implementation.
