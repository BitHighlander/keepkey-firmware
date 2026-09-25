# Handoff: executable ERC-7730 formatters for 7.15 (block 7 follow-up)

Date: 2026-09-25 · Owner decision: extend the 7.15 runtime (option 2) rather than only gate it.

- Repository: `/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware` (fork `BitHighlander/keepkey-firmware`).
- Branch: `release/715-stack-07-erc7730-core`, [PR #837](https://github.com/BitHighlander/keepkey-firmware/pull/837). Head when this handoff was written: `2781bb98d`.
- python-keepkey: branch `audit/715-stack07-remediation`, [PR #113](https://github.com/BitHighlander/python-keepkey/pull/113).
- Audit record: `docs/release/audit-units/715-07-full-audit-remediation-20260924.md`.

## 1. The problem this solves

The 7.15 ERC-7730 **signing runtime** executes only a narrow shape (`lib/firmware/fsm_msg_ethereum.h`, the display-instruction handler after `fsm_msgEthereumClearSignDefinitionChunk`):

- display program = intent (opcode 1), then fields (opcode 4), then end (opcode 10);
- every field formatter is kind 1 (raw), flags 0, exactly one argument of role 1 from source 1 (a path);
- every path is source 1 with 1–7 steps, all opcode 1 (index).

The **preload verifier** (`lib/firmware/erc7730_catalog.c`) accepts far more:

- formatter kinds 1–14 with their argument roles;
- display opcodes 2, 3, 5, 6, 7, 8 (interpolation, groups, iteration);
- conditions (section 5).

A signed definition using any of these loads fine. It then fails with "Unsupported ERC-7730 formatter/field instruction" **after** the user has approved the source, intent and earlier field screens. It fails closed (no signature), but the device has shown screens it cannot finish. Copilot flagged this class twice for narrower cases: the verifier/reader limits and the path step count, both fixed.

Measured against the official registry at pinned commit `9f37816afde954ff6617fb5baa346133e5af26c5` (1,450 calldata formats):

| Runtime supports | Formats fully signable |
| --- | --- |
| 7.15 today (raw only) | 92 (6%) |
| A: + addressName, tokenAmount | 853 (59%) |
| B: + interpolated intent (opcodes 2/3) | 1,007 (69%) |
| C: + amount, date, duration, unit, enum, nftName | 1,240 (86%) |
| D: + conditions, groups and iteration (opcodes 5–8), embedded calldata | 1,440 (99%) |

The remaining 10 are refused by the compiler for device limits: nested iteration and ABIs deeper than 8. Per-feature counts (formats using it): addressName 1,109 · tokenAmount 834 · raw 702 · date 84 · amount 80 · nftName 78 · unit 54 · enum 42 · embedded calldata 32 · duration 9. Opcodes 2 and 3 appear in 321 and 247 formats, opcodes 7 and 8 in 100, opcodes 5 and 6 in 24, and conditions in 68.

The PR #837 record's figure "1,440 reach firmware" means **pass the preload verifier**, not **signable**. Correct that wording in the first commit of this work.

## 2. Invariants (non-negotiable, carried from the block 7 audit)

1. **Additive only.** Annotations never suppress the ordinary review. `data_needs_confirm` stays forced; the final EIP-712 "Sign Typed Data" screen stays.
2. **One value tree.** Every displayed value is formatted from the same captured bytes that are signed, and the per-pass SHA-256 commitments stay (`erc7730_workflow.c`).
3. **No mid-review refusal.** Anything the runtime cannot execute is refused at preload, before the first screen. See §3.
4. **Injective text.** Every signer-authored or captured string goes through `erc7730_format_text()`. Long text is split into numbered parts, and each part is a required confirmation. Screen titles are device-owned.
5. **Trust labelling.** The runtime signer is *not* KeepKey-verified ("NOT verified by KeepKey"). Signer-supplied metadata (names, units, enum labels, messages) is shown as the signer's claim next to the raw value, never instead of it. Token and chain facts come only from firmware-owned tables (§4).
6. **Fail closed.** Any formatting failure aborts the workflow before a signature, and clears the preload.
7. **No flash writes, AdvancedMode required, preload lifetime unchanged** (discarded at every session boundary).
8. **Budgets** (measured at `2781bb98d` with CI's toolchain):
   - Full-product ARM ROM: 605,144 of 655,360 B used (~49 KB free).
   - SRAM reserve: 18,336 B against a 16,384 B floor. Any single change above 256 B needs owner review (`tools/sram-budgets.json`).
   - The deepest ERC-7730 display stack chain is ~4 KB.
   - Measure every phase with `tools/check_sram_budget.py` and `arm-none-eabi-size`. Prefer reusing the existing 513-byte formatted-value buffer over new static state.

## 3. Phase 0: one capability table, enforced at preload (do this first)

Create `include/keepkey/firmware/erc7730_capabilities.h` with a single `const` description of what this firmware executes:

- the permitted display opcodes and their operand shapes;
- the permitted formatter kinds and, for each, the permitted argument roles and sources;
- the permitted path step opcodes and the maximum step count;
- whether conditions are permitted.

- **Verifier.** `erc7730_catalog.c` rejects any program outside the table (formatters, display instructions, paths, conditions) with `ERC7730_CATALOG_BAD_PROGRAM`. The runtime then consults the *same* table, so the two cannot drift. At Phase 0 the table describes exactly today's raw subset. That is option 1 of the owner discussion, and it closes the mid-review failure immediately.
- **Paths against the ABI.** The verifier already parses the ABI node table. Walk every referenced path against it at preload: tuple index within `child_count`; array index within `array_length` or negative within it; the target must be a leaf the formatter accepts. This closes the remaining residual: a path naming a nonexistent index is currently caught only when that field is reached.
- **Host.** Give `tools/erc7730-validate` an executable mode driven by the same capability table. Add a python-keepkey registry test that asserts the *signable* count per phase (92 at Phase 0) next to the parse-conformance count. Each later phase raises the asserted number.
- **Test infrastructure (strongly recommended).** DebugLink exposes only OLED pixels, so wire tests cannot assert *what text* was shown. Add a DEBUG_LINK-only field to `DebugLinkState` carrying the last confirm title and body. That is a device-protocol change on the fork's canonical `master` per `docs/release/BRANCHING-SOP.md`, plus python-keepkey accessors. Every formatter phase below depends on exact-text assertions. Screen-count comparisons were shown to be weak in block 7: a count-only test passed on unfixed firmware.

Exit: registry signable = 92 exactly. Every program outside the table is refused at preload, and native plus wire tests show it happens before any ButtonRequest. Full native, both variants' integration suites, both ARM and SRAM gates, cppcheck 2.13 and clang-format 20 all pass.

### Phase 0 status (2026-09-25): implemented in block 7a (PR #837)

- `include/keepkey/firmware/erc7730_capabilities.h` / `lib/firmware/erc7730_capabilities.c` hold the table: display opcodes 1, 4, 10 (intent only at pc 0, fields without conditions), formatter kind 1 with one role-1 value argument, path source 1 with index steps, no conditions. The verifier (`erc7730_catalog.c`) and the runtime (`fsm_msg_ethereum.h`, `erc7730_workflow.c`) call the same predicates.
- The preload verifier walks every value path against the ABI. It keeps the walk table in the delegate-record buffer (`cert[]`, unused from the ABI section until the bindings), two bytes per node, so the verifier grows by one byte and SRAM does not change: the full-product reserve is still 18,336 B.
- The walk refuses a tuple index out of range, a step into a scalar, a fixed-array index outside `[-length, length)`, a dynamic-array index outside `[-64, 64)`, and a path that ends on a tuple or array.
- `tools/erc7730-validate` runs the device verifier, so it is now executable-mode by construction. python-keepkey mirrors the table as `erc7730_compiler.DEVICE_CAPABILITIES`; `compile_calldata`/`compile_eip712` refuse non-executable programs with `DeviceCannotExecute` unless `executable_only=False`. The registry test asserts that the device and the compiler agree on all 1,440 compiled formats in both directions, and that exactly 92 are signable.
- **Correction:** 92, not 94. Two 1inch `increaseEpoch(uint96)` formats show a raw field read from a container path (`@.from`, path source 2); the runtime never captured container values, so they would have failed mid-review. Container values (`@.from`, `@.to`, `@.value`) belong to a later phase.
- DebugLink: device-protocol `DebugLinkState.confirm_title` (16) and `confirm_body` (17), filled from the last `confirm_helper()` call in DEBUG_LINK builds only; python-keepkey `DebugLink.read_confirm_text()`.
- Tests: `Erc7730Catalog.PreloadRefuses*`, `PreloadWalksEveryPathAgainstTheAbi`, `RuntimePathPredicateMatchesTheTable`; wire tests `test_program_outside_capability_table_is_refused_at_preload`, `test_path_outside_abi_is_refused_at_preload`, `test_raw_field_screens_show_exact_text` in `scripts/emulator/test_stack07_regressions.py`. Negative controls: removing each verifier check fails a named unit test (the two formatter checks overlap and fail together); removing the capability checks or the walk and leaf check fails the matching wire test.

### Real per-phase targets (measured 2026-09-25 with the python mirror)

The plan's counts assumed values came only from calldata. Measured with container and literal sources: 0 = 92, A = 812 (a loose estimate gave 833; see below), B ≈ 987, C ≈ 1,172, D ≈ 1,383, E ≈ 1,412. The rest need nested iteration, ABIs deeper than 8, or reinterpretation the device will not do.

### Phase A status (2026-09-25): block 7b, stacked on 7a

- Table: formatter kinds 1, 3 (tokenAmount: value, token, threshold, message, native aliases) and 10 (addressName); path sources 1, 2 (containers `@.from`, `@.to`; calldata definitions only) and 3 (literals). `@.value` and `@.chainId` are left to Phase C; no registry format uses them with a Phase A formatter.
- Every argument is type-checked at preload (`erc7730_cap_value()`, shared with the runtime): the amount and the threshold are integers; the token and an addressName value are addresses; a raw literal is an integer, an address or a string reference; an alias set names at most `ERC7730_CAP_ALIAS_SET_MAX` (4) addresses. The verifier keeps a class per path in `signature[]` (idle from the ABI to the display section) and a class per literal in 32 bytes of nibbles.
- Runtime (`fsm_msg_ethereum.h`): each argument is resolved in its own definition replay or calldata/typed-data pass. The amount is copied out before the token pass, and every pass is hash-committed as before. The threshold message is fetched last, and only when the amount is at or above the threshold.
- Display (`erc7730_field.c`):
  - An address is always shown in full, EIP-55, with "(this wallet)" when it is the signing account, which is derived on device.
  - A token known to the firmware table for the chain is shown with that table's ticker and decimals, rendered as the ordinary Ethereum review renders it.
  - Any other token, including the zero address, is shown as the exact integer, then "unknown token" and its address.
  - A native alias shows the chain's native asset.
  - The threshold message appears above the value, never instead of it.
- Refused on purpose: 21 registry formats apply addressName to `uint256`/`bytes32` words that pack an address with flags (1inch), and 12 apply tokenAmount to encrypted `bytes32` amounts. Showing them would mean reinterpreting bytes the calldata does not declare as an address or an integer.
- Costs: SRAM reserve 18,336 → 18,208 B (−128 B). ROM text +4,096 B. The deepest new stack chain is definition chunk (2,320 B) → signer derivation (1,480 B) → key derivation.
- Behaviour change: `@.from` and "(this wallet)" derive the signing key during the review. With passphrase protection and no cached passphrase, the PassphraseRequest now comes during the review, not after it.
- Tests:
  - Native: `Erc7730Catalog.PreloadTypeChecks*`, `ContainersAreCalldataOnly`, `Erc7730Field.*` (EIP-55 spec vectors, firmware table entries, 2^256−1).
  - Wire, exact text:
    - `test_token_amount_uses_the_firmware_token_table`
    - `test_token_named_by_calldata_wins_over_the_hosts_claim`
    - `test_signer_label_cannot_name_an_unknown_token`
    - `test_threshold_message_is_shown_beside_the_exact_amount`
    - `test_native_alias_shows_the_chains_native_asset`
    - `test_address_name_marks_only_the_signing_account` (signer vs one byte off)
    - `test_containers_and_signed_constants`
  - Negative controls: forcing "(this wallet)", letting the message replace the value, ignoring aliases and dropping the verifier type check each fail the matching test.

## 4. Formatter designs and trust sources

| Kind | Name | Trust source | Display (body under a device-owned title; the signer's label leads) |
| --- | --- | --- | --- |
| 10 | addressName | None on device. There is no trusted name registry, and roles 12–14 (types and sources) are validated but give no authority. | EIP-55 checksummed address, always. Append "(this wallet)" only when it equals the signing account's address, computed on device. Never show a signer-supplied name without the address; if names are ever shown, label them "name from signer". |
| 3 | tokenAmount | Decimals and ticker **only** from the firmware token table (`tokenByChainAddress`, `lib/firmware/ethereum_tokens.c`) for the transaction's chain ID, or the role-11 chain resolved through the firmware chain table. | Known token: exact decimal amount with ticker, no rounding (reuse `erc7730_format_amount`, which is correct for 0–255 decimals). Unknown token: the raw integer plus "unknown token 0x…(EIP-55)". Role 22 native aliases map to the chain's native asset from the firmware chain table. Role 7/8 threshold message: show the message **and** the exact value; never replace the value. A 2^256−1 approve-like amount stays covered by the existing Stack 06 and EIP-712 permit policies. |
| 2 | amount (native) | Chain native symbol and decimals from the firmware chain table. | Exact amount with symbol. An unknown chain shows the raw integer in wei. |
| 5 | date | Role 9 encoding (timestamp or block height) from the signed program. | Timestamp: UTC `YYYY-MM-DD HH:MM:SS` with the raw integer. Block height: "block N". Refuse values that do not fit uint64. |
| 6 | duration | None needed. | `Nd Nh Nm Ns` plus the raw seconds. |
| 7 | unit | Roles 4–6 (base, decimals, prefix) are signer claims. | The formatted value with the unit escaped **and** the raw integer. |
| 8 | enum | Role 10 enum table from the signed program. | `label (value)`, escaped; an unmatched value shows the raw integer, labelled "unmapped". |
| 4 | nftName | No NFT registry on device. | Collection address (EIP-55) and token ID. Never a signer-claimed collection name without the address. |
| 13 | embedded calldata | Nested definitions, which need on-demand requests. | Phase E; see §6. |
| 9, 11, 12, 14 | chainId, tokenTicker, interoperable address, encrypted | Not used by the registry today. | Leave outside the capability table (refused at preload) until needed. |

Every formatted string reaches the screen through `erc7730_format_text()` escaping and part splitting. Add the formatters to `lib/firmware/erc7730_format.c`, which keeps them host-testable, not to the FSM.

## 5. Phases (each is a separate PR stacked on block 7, with its own audit)

- **Phase 0** (§3): capability table, preload enforcement, ABI path walk, executable-mode validator and signable-count test, DebugLink text capture. Signable: 92.
- **Phase A: addressName and tokenAmount.** Firmware token and chain lookups; unknown-token handling; threshold message plus value; "(this wallet)" match. Signable: 853.
  - Adversarial tests:
    - the host claims token X while calldata names token Y;
    - an unknown token;
    - the signer's label says "USDC" but the address is not USDC;
    - the threshold message would hide the value;
    - a native-alias spoof on another chain;
    - the address equals the signer vs differs by one byte.
- **Phase B: interpolated intent (opcodes 2 and 3).** The intent sentence is assembled from escaped fragments and the *same* formatted values the fields show, then split into parts. If any referenced value is not executable, the program is already refused at preload. ERC-7730 requires the plain intent as a fallback, so the verifier must require a plain intent string as well. Signable: 1,007.
- **Phase C: amount, date, duration, unit, enum, nftName** per §4. Signable: 1,240.
- **Phase D: conditions, groups and iteration (opcodes 5–8).** These need **owner decisions** first:
  1. Visibility rules (`never`, `ifNotIn`, `ifEmpty`) hide fields. The proposed policy: a condition may hide a field only when the hidden value is fully determined by signed constants. `mustMatch` is enforced as a constraint and refused on mismatch, never used to hide.
  2. Iteration needs a hard per-array element cap and a total-screen cap, both refused at preload when exceeded. Arrays are unbounded on the wire.
- **Phase E: embedded calldata (kind 13).** Needs nested definitions requested on demand during signing: a device-protocol change on the fork's `master`, a recursion/cycle cap, and a nested SHA-256 commitment. Out of 7.15 scope unless the owner decides otherwise. Signable after D and E: 1,440.

Per-phase exit criteria:

- signable count asserted exactly;
- every new formatter has spec-vector native tests from independent sources (the ERC-7730 spec and registry `testsv2` fixtures, never output of the code under test);
- a negative control for every new assertion, shown to fail with the protection removed;
- exact-text wire tests;
- OLED screenshots per the gate-3 rule (no firmware PR approval without OLED proof);
- ROM, SRAM and frame gates;
- the full CI graph green on the exact head;
- the audit SOP record, and a Copilot request only with explicit owner approval (one request per approval).

## 6. Protocol and host impact

- Phases 0–D need no new host messages: all data comes from calldata or typed data, the signed program and firmware tables. The only protocol change is the optional DEBUG_LINK text field in Phase 0.
- Phase E needs on-demand nested definition requests.
- python-keepkey's compiler (`keepkeylib/erc7730_compiler.py`) must stay in lockstep with the capability table: compile only what the target firmware executes, or report the exact reason. The desktop app should rely on the device's preload refusal and not assume registry coverage.

## 7. Known traps from block 7 (read before starting)

- A test gated by a missing input "passes" by skipping. The registry test always skipped until the validator existed; when it finally ran, 56 formats failed.
- Screen-count assertions can pass on unfixed firmware (raw glyphs page too). Assert exact text, or compare against a same-length ASCII control.
- `RESP_INIT` must never precede a `confirm()` in the same flow. A DebugLink `GetState` during a confirm memsets `msg_resp`, and dispatch clears the derived node. Derive, scrub, confirm, re-derive, then build the response.
- The verifier and every runtime reader must share limits. Three rounds of findings came from drift.
- cppcheck 2.13 (Ubuntu 24.04, CI flags) enforces zero findings. Reproduce it locally before pushing: it caught three findings that would have failed CI.
- `docker compose` integration needs ~10 GB free. A full host disk wedged Docker Desktop read-only.
- Local CI-equivalent run: `scripts/emulator` with `KK_FIRMWARE_VARIANT=full|bitcoin-only`, `KK_RELEASE_MISSING_CAPABILITIES` from `ci.yml`, and the registry checked out at the pinned SHA into `./build-inputs/erc7730-registry` (gitignored).

## 8. Open decisions for the owner

1. Approve Phase 0 as the immediate next step. It also resolves the mid-review failure class on the current PR.
2. The token trust source is the firmware token table only, never signer-supplied decimals or tickers. Confirm this.
3. The addressName policy shows the address always and never an unverified name alone. Confirm this.
4. The Phase D visibility policy (§5).
5. Whether embedded calldata (Phase E) is in or out of 7.15.
6. The SRAM review threshold per phase, given the current 1,952 B margin over the floor.
7. Whether phases ship inside block 7 (PR #837 grows) or as blocks 7a–7e stacked on it. Recommended: stacked PRs, each with its own audit record.
