# P06 Block 6 — frozen Ripple scope and audit inventory (7.15)

Status: local audit in progress. This is a finite Block 6 contract, not a full
Ripple or release-acceptance receipt. The review branch
`audit/715-p06-final-review` begins at the completed Block 4 head
`92931c91dc77bf2cdf80aaa8938b978add0cfde8`. Block 5 is deliberately
outside this review unit; this audit does not claim Block 5 was completed.
Current firmware source is `audit/715-scope-repair @
614425a2a14d0113de251e7944118e47f31f5265`; canonical product
`release/7.15 @ af979cd5099349ba58ec10d1b7eedeb67662c602` remains
separate. Remote identities were checked on 2026-09-22. The PR targets the
immediate predecessor `audit/715-p04-final-review` and changes audit artifacts
only.

The canonical main-worktree form is
`docs/release/MASTER-AUDIT-TEMPLATE.md`, SHA256
`dc484ea3bb7810b410c43830c307f032ad19276f81c7c6c123c407405d4b27e8`
at the pre-review check. The main copy adds a Block 00a progress note to the
committed snapshot; the template's numbered form sections are unchanged.
The main worktree has unrelated unresolved changes; the committed template at
`7d2c76bce1b49449cc80051cd431b7b1a487a1f3` supplies those same form
sections. The main copy remains the coordination authority.

## Selected behavior and invariant

Review four historical P06 units against the current 7.15 candidate: the host
Ripple memo assertion must execute on the full variant; a displayed address
must survive DebugLink requests while confirmation is pending; the permanent
host test must assert the returned address; and XRPL variable-length encoding
must use one byte at length 192 and two from 193. The full-variant restriction
is intentional: Bitcoin-only does not ship Ripple. The physical OLED display,
other-release behavior, and wider Ripple/client audit remain separate release
or follow-up work, not implicit passing results here.

## Historical unit inventory

Each SHA below is an ancestor of the current candidate. Counts are per-commit
`git show --format= --numstat --no-renames COMMIT`, including docs, tests, and
submodule pointer lines; they are not a net candidate diff.

| Unit | Commit | + / - | Current disposition |
| --- | --- | ---: | --- |
| P06-001 host memo coverage | `7a8a873c366c1c7844b2a414a4fa187c5617cba5` | 22 / 1 | Historical host pin superseded; verify the memo test runs in current Python pin. |
| P06-002 displayed-address response | `885609fbe2ddf66b5224f76880d2c8ff3b90eec1` | 27 / 4 | Retained local address copy and response-after-confirmation order. |
| P06-003 permanent host display assertion | `cecf1ea20239d140cb43dc0629219fd9179ae452` | 16 / 1 | Historical host pin superseded; verify current test executes and asserts. |
| P06-004 192-byte memo prefix | `39503dacf595821b2b8a1c65e3f44fa9b6352a88` | 37 / 1 | Retained `<= 192` boundary and 191/192/193/199 native vector. |

Later candidate changes affecting these surfaces include `6e79e57b7` (Ripple
amount bound and native regression) and the later canonical Python pin. Review
interactions rather than inferring
survival from historical ancestry. The general serializer's maximum-length
helper domain is not reached by the 7.15 memo[200] field and remains outside
this P06 memo-boundary receipt.

## Frozen dependency pointers

| Dependency | Candidate pin |
| --- | --- |
| `code-signing-keys` | `a6470bd8598e5e9a7bfc38bf139a5e5a616f05ec` |
| `deps/crypto/trezor-firmware` | `8a392f70a5d5575ece3dfb35f115d4a4b27f497c` |
| `deps/device-protocol` | `27d3fa1f6215139cde6411f9a2882f36bb373fc9` |
| `deps/googletest` | `7888184f28509dba839e3683409443e0b5bb8948` |
| `deps/python-keepkey` | `b76ee610dd18934ee3aeeb36cfc541e8799eb46d` |
| `deps/qrenc/QR-Code-generator` | `6dfbfdad5d9303ed190d1c3cb7bec34b565b6ce8` |
| `deps/sca-hardening/SecAESSTM32` | `71d356a1141624994cf613bd2d2583892e8e6d5a` |

## Acceptance checks

1. Trace current `fsm_msg_ripple.h`, `ripple.c`, registered native vectors and
   current Python host tests. Record any concrete finding and its disposition.
2. Verify full and Bitcoin-only test execution/skips, host address/memo/sign
   assertions, native/board and ARM/SRAM results; identify exact artifacts and
   code/test/pin equivalence. Keep physical OLED and signed hardware as gates.
3. Compare the 192/193 boundary with the [XRPL Binary Format](https://xrpl.org/docs/references/protocol/binary-format#length-prefixing),
   which defines one byte for 0–192 and two bytes for 193–12480.
4. Publish the canonical Git inventory, readable report and PDF, inspect the
   render, and complete the local preflight before one planned Copilot request.

## Current-source reconciliation and finding disposition (2026-09-22)

`fsm_msgRippleGetAddress` derives into a local `ripple_addr[MAX_ADDR_SIZE]`,
keeps it through `confirm_ethereum_address`, and fills the shared response
only after confirmation; cancellation clears the derived node and returns a
failure. The current pinned Python test asserts the known returned address
when display is requested on firmware 7.14.2 or later. The current memo host
test requires the full variant and 7.15.0, asserts the serialized Memos tail
and its absence in a plain send, and has no unconditional skip. The current
`ripple_serializeVarint` uses `<= 192`; the native vector covers 191, 192,
193, and 199. The later Ripple amount-bound change does not undo these paths.

**P06-F001 — accepted scope limit / follow-up:** the generic three-byte helper
uses `< 918744` although the XRPL Binary Format includes 918744, and its
debug-only buffer assertion is stricter than the underlying checked append
when exactly three bytes remain. No 7.15 Ripple call site reaches this range:
the memo field is capped at 200 bytes including its terminator, while address,
public key, and signature fields are shorter. This is a concrete helper-domain
edge for a separate full Ripple serializer review, not evidence that P06-004's
reachable 192-byte memo boundary failed. It is not described as fixed or
waived by this unit. No new defect in the selected P06 behavior was identified.

## Executed evidence and remaining gates

The pinned full owned emulator image
`sha256:18f7375986270c6bdcea6155e9fe8382d5a4faca8f0466ff3bf727b759a2e9f3`
ran current host `test_ripple_show_address` with `KEEPKEY_SCREENSHOT=1` and an
exact test selector: **1 passed, 2 deselected**, with one captured PNG. The
JUnit SHA256 is `3c2897b104ba4d8744379d810bb49114993cdc3a14344c31e6ca39f1bfd3ff4b`;
the visually inspected PNG SHA256 is
`8ab53a8b93f7020b1e14f43a943950f27618e10b2d21a6f3ce4c2404f6802a6d`.
The PNG is included as `P06-ripple-show-address-20260922.png` beside this
receipt, so the captured screen is reviewable with the PDF.
The same image ran `test_sign_with_thorchain_memo`: **1 passed, 3 deselected**,
JUnit SHA256 `73d618dfdfe7a2e68d9d0350f9fa9a654525820ac16ed6eabc86b1711d205ff3`.
The owned results are at `/private/tmp/kk-fw-715-p06-evidence` and run the
same source/tests/pins as this docs-only branch.

The full candidate `make xunit` log executes and passes
`Ripple.MemoLengthPrefixBoundary` and the other four Ripple native cases; its
total is 573 firmware, 17 board, 18 crypto, and 6 Pallas passes, log SHA256
`5a452156d0b2264f480ac5d640e388e1ea9ab10bf57783751bcde2fbe947459d`.
Ripple native tests are excluded from the Bitcoin-only target by design;
Bitcoin-only still passes its 131 firmware, 17 board, and 18 crypto suite,
log SHA256 `4509a2ef1d05d5cdfa21401a6350fd562a48b1b6e69be3dcb14f211ee25ff49e`.

Earlier firmware-equivalent CI
[run 34951131013](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34951131013)
at `7e091af157131897adc5514de392570c32088946` records passing full-host
Ripple address/display/sign/memo cases in artifact `10390030970`. Its
Bitcoin-only host artifact `10389023825` skips all seven Ripple cases as
expected. Full and Bitcoin-only native artifacts are `10388679573` and
`10389512420`; ARM firmware artifacts are `10389287571` and `10388589162`.
Full ARM job `104322245689` and Bitcoin-only job `104322245632` both concluded
success, including cross-compile and SRAM budget steps. From the CI source to
the pinned candidate only CI workflows changed; from the owned-image source
to this review branch only audit documents/SOP changed. These are supporting
code/test/pin-equivalent results, not exact-head workflow certification.
Physical OLED behavior, signed-device upgrade, full Ripple helper-domain
review, and final exact-workflow CI remain separate release/follow-up gates.
