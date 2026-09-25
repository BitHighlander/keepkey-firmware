# Handoff: ERC-7730 embedded calldata (Phase E): goals, needs, hard requirements

Date: 2026-09-25. Status: **framing only; nothing is designed or decided.** Blocks 7a (#837) and 7b (#863) are the base. Phase 0–D status is in `HANDOFF-ERC7730-715-FORMATTERS.md`.

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
- Phase A–D blocks 29 of the formats. Of the remaining unsignable formats, about 130 are refused on purpose: slices, packed words, nested arrays, ABIs deeper than 8.
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

## 9. Decisions needed from the owner before design

1. **P5:** without an inner definition, show the minimum (callee, selector, value, operation, bytes hash or data) with a "not clear-signed" label, or refuse?
2. **P4:** is a device-protocol change on the canonical branch acceptable if the existing request is not enough?
3. **P7 and P8:** first cut = single embedded call in calldata only, or include `multicall` and/or EIP-712 `SafeTx.data`?
4. **P6:** confirm the one-level cap.
5. **H9:** is the 256 B review threshold the budget for the resident set, or is a stated larger number acceptable with review?
