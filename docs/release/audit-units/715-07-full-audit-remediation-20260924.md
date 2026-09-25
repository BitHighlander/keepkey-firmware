# Stack 07 full code audit and remediation — 2026-09-24

## Scope and identity

This records an owner-requested full code audit of [PR #837](https://github.com/BitHighlander/keepkey-firmware/pull/837) at `9e9ccecac878b3760e971b81fef095870362e291`, over its 53-path diff from the Stack 06 base `efdeb678bc33c616cf8048fb5773548f0da96fa7`, and the remediation of every finding. It was run after the second Copilot review had been dispositioned. It is not a Copilot review and does not count as one.

Five independent read-only reviewers covered streamed EIP-712, the ERC-7730 catalog and program interpreter, the ABI decoders and formatters, the signing-flow integration, and the test/CI/report evidence. The top findings were re-read against the source before remediation began.

Remediation commits on top of `9e9ccecac`:

- `2621b80b3` — firmware and native tests.
- `33373fbf9` — CI, tooling, the Stack 07 wire regressions and the python-keepkey pin `1d42a1fa4` → `4f80b087f643df713fb8492b463e6f885d2e90bc` (BitHighlander/python-keepkey branch `audit/715-stack07-remediation`).
- The commit containing this document — corrections to the Stack 07 review and retrospective.

## Findings and dispositions

| # | Sev | Finding at 9e9ccecac | Disposition and evidence |
| --- | --- | --- | --- |
| 1 | P1 | Streamed EIP-712 screens were titled with the bare member name: the primary type was hashed but never shown, domain and message were indistinguishable, array elements were all titled "item", and there was no signer or final approval screen. `Deposit` and `Withdraw` with identical members drew identical screens. | Fixed. Every leaf is titled with the domain or the primary type and its body opens with the full path (`from.wallet`, `to[1].wallet`). One final "Sign Typed Data" screen names the primary type and the checksummed signing address on every signature; declining returns no signature. Native and device tests. |
| 2 | P1 | An ERC-7730 `string` capture with an embedded NUL was accepted (valid UTF-8) and `confirm("%s")` stopped at it: the device showed a prefix of what the contract receives. The raw review that follows shows only a data hash. | Fixed. `erc7730_format_text()` refuses NUL, C0 and DEL and escapes the rest. Native tests. |
| 3 | P1 | The python-keepkey assertion "unlimited approval refused with no ButtonRequest" could not fail: the expected-response exception embeds the expected text, so `assertIn` passed for any device response. | Fixed in python-keepkey `546dcb0`: the request is sent raw and the first response must be exactly `Failure_ActionCancelled` "Unlimited ERC20 approval is disabled". Shown to fail on a wrong message and a wrong code. The firmware behaviour itself was correct. |
| 4 | P2 | An unused preloaded ERC-7730 definition survived Initialize, Cancel, ClearSession, autolock and unrelated requests, pulling the next ordinary request onto the certified path. | Fixed. Dispatch discards it for every request other than its own chunks, `EthereumSignTx` and `EthereumSignTypedData`; every session boundary discards it. `Fsm.Erc7730PreloadEndsAtEverySessionBoundary` plus a wire test. |
| 5 | P2 | `approve()` was recognised only with 12 zero bytes after the selector. A dirty spender word, which pre-0.8 Solidity masks, skipped the unlimited-allowance guard and reached generic hash-only signing. Present before this stack. | Fixed. The selector alone selects the allowance policy; a non-canonical spender word is refused before any screen. `Fsm.DirtySpenderWordCannotBypassApprovalPolicy` plus a wire test. |
| 6 | P2 | Typed-data permits were outside the unlimited-approval policy, and they sign without AdvancedMode. | Fixed by owner direction ("fix them all"). Unlimited EIP-2612 `Permit.value`, DAI `Permit.allowed = true` and Permit2 `PermitDetails`/`TokenPermissions.amount` are refused before that leaf's screen. Native tests cover all four; device tests cover EIP-2612 and Permit2. |
| 7 | P2 | The OLED font draws every non-ASCII byte as one glyph and the pager drops leading spaces, so distinct strings could draw the same screen. | Fixed for EIP-712 and ERC-7730 strings: non-ASCII bytes, backslash and edge or doubled spaces are escaped. The board pager is unchanged. |
| 8 | P2 | `confirm()` refuses a body of 352 characters or more, so EIP-712 `bytes` over about 170 bytes and long strings were refused and reported as a user cancel, and ~3 KB of stack buffers could never be used. Seaport was listed as supported but could never fit 12 slots. | Fixed. Long values are shown in numbered parts, each a required confirmation; a value that cannot be displayed is a validation failure, not a cancel. `EIP712_MAX_SLOTS` is 24, which fits Seaport orders of up to seven items. Native and device tests. |
| 9 | P2 | ERC-7730 trust gaps: EIP-712 definitions with a zero header contract ignored their signed deployments; revocation epochs and `provider_id` were parsed but unenforced; delegate-cert scope bytes were unauthenticated while a test claimed otherwise; the displayed signer fingerprint was 32 bits. | Deployments are enforced: a definition applies only at a signed deployment matching the typed data's chain and verifyingContract. `ERC7730_MIN_ISSUANCE_EPOCH` gives a firmware-update revocation lever (currently 0); revocation epoch and `provider_id` are documented as unenforced. The Vault certificate carries data in the unchecked cert bytes, so they are documented rather than zero-checked, and the overclaiming test now asserts only what is signed. Fingerprints are 64 bits. |
| 10 | P2 | Evidence errors: the pin was only on an unmerged branch with no PR; the review doc misattributed the CoinTable and lint fixes to `de7457b5d` and described the review of `9e03d46ab` as coming after it; Stack 07 counts were stale; the firmware validator required by the compiler conformance tests did not exist, so those tests always skipped; a Stack 07 array test was gated on a later block's capability. | SHAs, counts and the pin statement are corrected in the review and retrospective. The new pin is published and carried by draft [python-keepkey PR #113](https://github.com/BitHighlander/python-keepkey/pull/113). `tools/erc7730-validate` runs programs through the firmware's catalog verifier, and CI requires it on the full product. The array test is gated on what it needs and now checks digests against an independent encoder. |
| 11 | P3 | Test and display gaps: no Merkle-proof or most negative-authentication coverage; the streaming ABI decoder lacked the validator's negatives; integers shown as hex; addresses without EIP-55; verifier and replay-reader limits disagreed; runtime labels were used as screen titles; zero literals compared inconsistently; `primaryType: "EIP712Domain"` signed the wrong digest; an unreachable in-progress check; wire refusals asserted only the Failure type; the CoinTable variant was inferred from the device; the contract JUnit files were not required by the report. | All fixed with tests; see the commit messages. ERC-7730 amounts remain in base units, because 7.15 executes only the raw formatter and has no token records to scale by. |

## New defect found by the new evidence

Once the firmware validator existed, 56 of the 1,450 official registry calldata formats compiled to programs the device refuses: 46 `tokenAmount` fields with no token (formatter kind 3 needs a token argument), 8 paths iterating two nested arrays (the verifier accepts one `[]` step per path) and 2 ABIs nested deeper than eight levels. The earlier claim that all 1,450 formats reach firmware had never been checked. The compiler now emits the raw formatter when no token is named, and refuses the other two shapes by name. The registry test requires every format to pass the firmware validator or be one of those 10 named refusals. "Pass the firmware validator" means the device's preload verifier accepts the program; it does not mean 7.15 can sign it. The 7.15 signing runtime executes only raw fields with index paths, which is 94 of the 1,450 formats. Programs using the other formatters, interpolation, groups, iteration or conditions load and then fail after earlier screens. The owner chose to extend the runtime; the plan is `docs/security/HANDOFF-ERC7730-715-FORMATTERS.md`.

## Verification

All local runs used the CI base image `kktech/firmware@sha256:7438e539…`.

- Native, full: firmware-unit 622, board 19, crypto 18, Zcash crypto 72, all passing. Bitcoin-only: 135, 19, 18.
- Negative controls: the new EIP-712 walk, preload-lifetime and dirty-spender native tests, every new or changed wire assertion, and the compiler conformance suite (run against an always-refusing validator) were each shown to fail with the protection removed. The ERC-7730 native tests use hand-built fixtures and spec vectors, not output of the code under test.
- ARM MinSizeRel links and `tools/check_sram_budget.py`: full reserve 18,336 B (was 18,896 B), largest frame 7,664 B, pass; Bitcoin-only 39,136 B (unchanged), pass.
- Stack along the certified-calldata path: `fsm_msgEthereumTxAck` 1,448 + `confirm_erc7730_intent_and_continue` + `continue_ethereum_sign_tx` 256 + `ethereum_signing_init` 416 + `confirm` 304 + drawing. That is about 4 KB including the 513-byte formatted-value buffer, well inside the reserve.
- cppcheck 2.13 (Ubuntu 24.04, CI flags): zero findings. clang-format 20: clean on every changed file. actionlint and shell syntax: clean.
- CI-equivalent `docker compose` integration on the committed head, both variants: results are recorded in the PR description with the hosted run.

## Copilot review of the remediated head

The owner authorized one request on `f600da9d9`. [Review 5313258873](https://github.com/BitHighlander/keepkey-firmware/pull/837#pullrequestreview-5313258873) (Lite) returned **Changes recommended**. It listed all seven second-round findings as resolved and raised three new ones. All three were real:

| Comment | Finding | Disposition |
| --- | --- | --- |
| 4100999029 | ERC-7730 intent text and field labels reached the screen raw, although the catalog accepts non-ASCII bytes and edge or doubled spaces in program strings. | Fixed. Intent and labels go through `erc7730_format_text()` like values and split into numbered screens when long. The official registry uses edge spaces as sentence fragments in 379 of its 6,396 compiled strings, so the verifier does not reject them. The registry has no non-ASCII or doubled spaces, so real descriptors display unchanged. Wire test `test_non_ascii_intent_is_escaped_not_drawn_as_glyphs` compares against a same-length ASCII intent. It fails on `f600da9d9`, where both drew the same number of screens (4 and 4), and passes after the fix (8 and 4). |
| 4100999081 | Bitcoin-only runs required the ERC-7730 registry that only the full product uses. | Fixed. The registry export and check, and the CI fetch and pin check, now run only for the full variant. |
| 4100999118 | The report's JUnit reader let a later duplicate testcase overwrite an earlier failing one. | Fixed. Duplicate testcases are refused. A synthetic duplicate is rejected, the real Stack 06/07 files contain none, and the report validator tests pass. |

## Copilot review of the round-3 fixes

On owner approval, [review 5313747274](https://github.com/BitHighlander/keepkey-firmware/pull/837#pullrequestreview-5313747274) (Lite) on `a74532eb9` marked all three round-3 findings resolved and raised two new ones:

| Comment | Finding | Disposition |
| --- | --- | --- |
| 4101396205 | The typed-data response was initialised in the shared `msg_resp` arena before the final "Sign Typed Data" confirmation. A DebugLink `GetState` answered during that screen runs `RESP_INIT` on the same arena. | Real, introduced by this remediation, and limited to DEBUG_LINK builds. The address is now kept in a local, the node is scrubbed before the confirmation and derived again after approval, and the response is built only after signing. The pyk streaming tests now also assert the reported address. Under screenshot capture, which reads state at every button request, `a74532eb9` returned an empty address and 5 of 5 signing tests failed; the fix passes 5 of 5. |
| 4101396237 | `python-keepkey-tests.sh` was said to run contract JUnit validation before those files exist. | Not a defect. The script calls python-keepkey's report script, which has no contract validation. The firmware `scripts/generate-test-report.py` that holds `validate_contract_junit()` runs only in CI's `generate-test-report` job, after both integration legs upload their JUnit files. Hosted runs 36085522402 and 36096967483 and the local compose run all passed through this sequence. |

## Final owner-approved Copilot review

[Review 5314053769](https://github.com/BitHighlander/keepkey-firmware/pull/837#pullrequestreview-5314053769) (Lite) on `197df86a2` marked both round-4 findings resolved and raised two new ones:

| Comment | Finding | Disposition |
| --- | --- | --- |
| 4101618988 | An initial `EthereumClearSignDefinition` was said to leave an older non-idle `Erc7730Workflow` alive, so the following `SignTx` would clear the new preload. | Not a defect. Dispatch calls `abort_signing_engines()`, which calls `ethereum_signing_abort()`. That aborts any non-idle workflow (`ethereum.c`), and the abort clears the old preload, before the new definition's handler runs. `Fsm.Erc7730PreloadEndsAtEverySessionBoundary` now pins this: a workflow in REPLAY is IDLE after the definition's dispatch, and a following `SignTx` keeps the new preload. |
| 4101619035 | The catalog verifier and replay reader accepted up to 16 path steps (`ERC7730_ABI_MAX_PATH`), while calldata and typed-data captures refuse `ERC7730_ABI_MAX_DEPTH` (8) or more. A signed program could therefore pass preload and fail mid-review. | Real. The verifier, the reader and the host compiler now all refuse 8 or more steps; each step descends one ABI level, so no valid path is that long. `Erc7730Catalog.PathStepLimitMatchesExecutionCaptures` accepts 7 steps and refuses 8, and it fails with the old limit. No official registry format is affected: 1,440 still pass the preload verifier (94 are signable on 7.15) and 10 are refused for named limits, as before. |

## Open items for the owner

- Signing runtime coverage: 7.15 signs only 94 of the 1,450 registry formats. Other programs pass preload and fail mid-review. The owner chose to extend the runtime; the phased plan is `docs/security/HANDOFF-ERC7730-715-FORMATTERS.md`.

- SRAM: the full product's reserve fell by 560 B. `tools/sram-budgets.json` requires explicit review of any single-commit increase above 256 B; 384 B of it is the Seaport-capable slot pool.
- `increaseAllowance`, `setApprovalForAll` and Permit2 `approve` calldata are still outside the allowance policy. That predates this stack and was not an audit finding against it.
- Physical-device verification, including OLED photographs of the new typed-data screens, has not been done.
- Copilot has not reviewed the fix for its final-round finding. The owner designated review 5314053769 as the last authorized request.
