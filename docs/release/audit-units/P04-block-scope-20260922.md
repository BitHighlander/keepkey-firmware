# P04 Block 4 — frozen scope and evidence inventory (7.15)

Status: current-source audit in progress. This is the finite-batch contract,
not release acceptance. Audit branch `audit/715-p04-final-review` begins at
`7d2c76bce1b49449cc80051cd431b7b1a487a1f3`, the completed P03 head plus
canonical SOP/template commit. The immediately reviewed P03 head is
`5b5a9c1b196f82a6a98e07f6ba2729560aeafe89`. Candidate firmware source is
`audit/715-scope-repair @ 614425a2a14d0113de251e7944118e47f31f5265`;
canonical product `release/7.15 @ af979cd5099349ba58ec10d1b7eedeb67662c602`
remains separate. Remote heads were checked on 2026-09-22. This review PR will
be stacked on `audit/715-sop-review-budget`, without moving product or develop.

Main-worktree master template:
`/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware/docs/release/MASTER-AUDIT-TEMPLATE.md`,
SHA256 `8c6ef0cdb27bc028befec2c4614f3bb9b672010e84fd797c829dea83b1c88315`.
The main worktree has unrelated unresolved changes; the tracked snapshot is
`docs/release/MASTER-AUDIT-TEMPLATE.md` at the frozen predecessor.

## Selected behavior and invariant

Audit retained P04 Bitcoin transaction input-history tracking, rejection of a
duplicate output with changed inputs, extended-wallet mixed-mode change path
classification, exact transaction-ID byte hashing, and shared Bitcoin-only
emulator transport initialization. A transaction's input digest must remain
stable across all its outputs; a refused output must not become the accepted
comparison key; an extended derivation prefix must match before an output is
considered change; the digest must hash exactly the transaction ID bytes; and
both native variants must execute the registered regressions.

## Historical unit inventory

All commits below are ancestors of the frozen candidate. Counts are from
`git show --format= --numstat --no-renames COMMIT`, including tests; repeated
edits overlap and are not a net candidate diff.

| Unit | Commit | + / - | Candidate disposition |
| --- | --- | ---: | --- |
| Preserve input history across outputs | `29e14b4a417875495bbb5d029e844294f05125c9` | 56 / 35 | Retained: finalize a hash snapshot, reset at signing boundary, save output comparison key without resetting the current hash. |
| Preserve accepted history on refused output | `b57eb71c2ee1babfeb20805b7f6b64ad70c4e925` | 19 / 2 | Retained: save only after duplicate-output refusal is ruled out. |
| Preserve extended wallet prefix for mixed-mode change | `a1e7f53155ee3db53991f9d45349eb47e5e1ef90` | 53 / 0 | Retained: reject mismatched leading path components. |
| Bound input-history digest to transaction ID | `c46ae0aad3158884a1a049db016bfc200d2d33e6` | 1 / 1 | Retained: hash `prev_hash.bytes` size rather than a type size. |
| Share Bitcoin-only emulator transport setup | `039e2f9644876443ad1c5ad78082cee0e8901cba` | 0 / 6 | Retained test cleanup; verify the shared setup executes in both variants. |

Later changes touching P04 surfaces include `533b38eb1` (input multisig
quorum), `49930bc8a` (sighash suffix bounds), `0a7e0cf4a` (workflow timer),
and `64e5d2cb2` (final release audit). Trace their interactions in the current
candidate before declaring the historical units accepted.

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

1. Trace current `signing.c`, `transaction.c`, and `txin_check.c` state paths,
   including start/abort, OP_RETURN, accepted and refused outputs, and
   extended BIP32 paths. Disposition every concrete finding.
2. Confirm `signing.cpp`, `transaction.cpp`, and `usb_rx.cpp` registration and
   execution in full and Bitcoin-only variants. Check native, board, host,
   ARM/SRAM, CI artifacts, and skips under the master template.
3. Compare the exact code/tests/pins at this branch with the owned emulator
   images and the earlier firmware-equivalent CI before carrying evidence.
4. Produce the Git-reproducible audit report and PDF, render-check the PDF,
   perform the canonical local preflight, and only then enter the final review
   checkpoint within the SOP request budget.

## Current-source and executed-test check (2026-09-22)

Current `txin_check.c` finalizes a copy of the input SHA256 context, so each
output compares the same inputs. `signing_init` and `signing_abort` reset only
the in-progress digest; `transaction.c` leaves OP_RETURN without a payment
comparison key and saves an accepted payment key only after duplicate-output
refusal is ruled out. The mixed-mode path helper checks `count >= 5`, equal
path lengths, and the leading `(count - 5)` components before allowing the
script-purpose variation. The phase-one signer hashes
`sizeof(tx->inputs[0].prev_hash.bytes)`, the actual transaction-ID byte array.
Later multisig quorum and sighash-suffix changes are separate guards in the
same signer and do not remove these P04 checks. No new in-scope defect was
identified by this path review.

Both full and Bitcoin-only native targets register `signing.cpp`,
`transaction.cpp`, and `usb_rx.cpp`. In the exact pinned candidate emulator
images used for P03, `make xunit` logs show executed passes for
`Signing.MixedModeChangeMustPreserveLeadingPathComponents`,
`Transaction.ChangedInputsTriggerDuplicateOutputRefusal`,
`Transaction.IdenticalOutputsWithinOneTransactionKeepInputHistory`, and
`USBRX.TinyAcknowledgementDoesNotReusePreviousSecret` in **both variants**.
The full run passed 573 firmware, 17 board, 18 crypto, and 6 Pallas tests;
Bitcoin-only passed 131 firmware, 17 board, and 18 crypto. Full and Bitcoin-only
image IDs are `sha256:18f7375986270c6bdcea6155e9fe8382d5a4faca8f0466ff3bf727b759a2e9f3`
and `sha256:12d356b3912a0e7f76923db50368ee66e979fed3935174b6084726090a8f99db`.
Log SHA256 values are `5a452156d0b2264f480ac5d640e388e1ea9ab10bf57783751bcde2fbe947459d`
and `4509a2ef1d05d5cdfa21401a6350fd562a48b1b6e69be3dcb14f211ee25ff49e`.
The logs are retained at `/private/tmp/kk-fw-715-p03-owned-evidence`.

Earlier firmware-equivalent CI
[run 34951131013](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34951131013)
at `7e091af157131897adc5514de392570c32088946` has full and Bitcoin-only
unit artifacts `10388679573` and `10389512420`, full and Bitcoin-only host
artifacts `10390030970` and `10389023825`, and full/Bitcoin-only firmware
artifacts `10389287571` and `10388589162`. Both host JUnit files record
`test_msg_signtx.test_one_one_fee` passing; the Bitcoin-only host JUnit also
records `test_bitcoin_signing_survives_the_strip` passing (it is expectedly
skipped in the full variant). `7e091af15..614425a2a` changes only two CI
workflow files, so this is code/test/pin-equivalent supporting evidence, not
exact-workflow certification. `350ccf3a7..` this review head changes only
audit documentation/SOP, so the pinned owned-image native results carry for
P04. Physical signing review and signed-device upgrade remain release gates.
