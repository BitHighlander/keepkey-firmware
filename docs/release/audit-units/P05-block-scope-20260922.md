# P05 Block 5 — Zcash viewing-key authorization scope (7.15)

Status: local current-source review in progress. No pre-existing P05 scope,
branch, or PR was found on the fork when this unit began. The owner selected
inference from candidate history; this receipt assigns the named Zcash
viewing-key consent and account-identity gap to Block 5. It does not claim
that an earlier historical unit used the P05 label.
The isolated worktree is `/private/tmp/kk-fw-715-p05-review`, branch
`audit/715-p05-final-review`, based on the completed P04 head
`92931c91dc77bf2cdf80aaa8938b978add0cfde8`. Candidate source is
`audit/715-scope-repair @ 614425a2a14d0113de251e7944118e47f31f5265`;
canonical product `release/7.15 @ af979cd5099349ba58ec10d1b7eedeb67662c602`
is separate. These remote heads were checked on 2026-09-22. No product or
fork `develop` branch is advanced by this document.

The canonical main-worktree master template is
`/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware/docs/release/MASTER-AUDIT-TEMPLATE.md`,
SHA-256 `5503bc620856323eaa569dfb86016ae6275421a962c52b8e7eb1a65dc8ba63e4`.
The main worktree has unrelated merge conflicts; the matching tracked snapshot
is committed on this isolated branch. `docs/release/REHEARSAL-SOP.md` matches
the main copy. The main template records the completed 00a/P02/P03/P04
checkpoints and keeps P01, P05, and P06 distinct.

## Selected behavior and invariant

Audit the retained Zcash Orchard full-viewing-key export boundary and shared
account resolution in the current 7.15 full variant. A host-provided
`show_display=false` must not waive device consent before viewing-key export.
An explicit account value with the hardened bit set must be rejected rather
than aliasing a lower account. The shared resolver is used by
`ZcashSignPCZT`, `ZcashGetOrchardFVK`, and `ZcashDisplayAddress`. The
Bitcoin-only variant has no Zcash messages. This scope does not reopen
Orchard cryptography, nonce generation, PCZT transaction authorization, or
the inherited storage durability design; later edits on the same handler
must still be reconciled for interaction.

## Frozen historical unit and current-source reconciliation

| Unit | Commit | Files and Git counts | Current disposition |
| --- | --- | --- | --- |
| Viewing-key consent and account identity | `d4c82dd33fabe84c41151bf73eb322839dff9660` | `deps/python-keepkey` +1/-1 submodule pointer; `docs/release/audit-units/zcash-export-authorization.md` +16/-0; `lib/firmware/fsm_msg_zcash.h` +9/-2. Reproduce with `git show --format= --numstat --no-renames d4c82dd33fabe84c41151bf73eb322839dff9660`. | Retained in the frozen candidate. The FVK handler always calls `confirm` before deriving or sending keys; `zcash_resolve_account` rejects the explicit high bit before returning an account. |

Before this unit, the host could suppress FVK confirmation and supply an
explicit high-bit account that aliased a lower index. The unit makes export
consent unconditional and rejects aliased explicit indices. This matters
because FVK bytes disclose wallet activity and the account identity must be
unambiguous. The unit receipt records controls that failed before the fix.
Its historical Python pin `b6253211465f0cd935945ce4e82fc7a17e4071ab`
was later superseded by the candidate pin below; current tests are inspected
and executed at the current pin, rather than inferred from the historical one.

Later `fsm_msg_zcash.h` edits `1c67a2a60` (Orchard action validation),
`7295f534c` (transparent-input refusal), and `c3ec59c35` (cross-workflow
acknowledgements) touch nearby code but do not remove the shared account
resolver or the FVK confirmation. They remain separate behavior and release
review surfaces. Current source: `lib/firmware/fsm_msg_zcash.h:187-216,
959-1015` for this block; resolver callers are also at `:648-650` and
`:1024-1034`.

## Candidate dependency pins

| Dependency | Pin |
| --- | --- |
| `code-signing-keys` | `a6470bd8598e5e9a7bfc38bf139a5e5a616f05ec` |
| `deps/crypto/trezor-firmware` | `8a392f70a5d5575ece3dfb35f115d4a4b27f497c` |
| `deps/device-protocol` | `27d3fa1f6215139cde6411f9a2882f36bb373fc9` |
| `deps/googletest` | `7888184f28509dba839e3683409443e0b5bb8948` |
| `deps/python-keepkey` | `b76ee610dd18934ee3aeeb36cfc541e8799eb46d` |
| `deps/qrenc/QR-Code-generator` | `6dfbfdad5d9303ed190d1c3cb7bec34b565b6ce8` |
| `deps/sca-hardening/SecAESSTM32` | `71d356a1141624994cf613bd2d2583892e8e6d5a` |

## Local evidence and remaining checks

The full pinned emulator image
`sha256:18f7375986270c6bdcea6155e9fe8382d5a4faca8f0466ff3bf727b759a2e9f3`
ran the two direct host regressions in
`deps/python-keepkey/tests/test_msg_zcash_orchard.py`: **2 passed**, 5
deselected. Running the complete Orchard FVK, fingerprint, device PCZT and
address-display files together yielded **21 passed**. The saved full-run log
is `/private/tmp/kk-fw-715-p05-evidence/host-full.log`, SHA-256
`f3c14ad15838f4c7165881da5ceaf6ea1dba15fe3c8f5830915d5dfa24443ea6`.
Each run started the image's own `/kkemu/bin/kkemu` and used
`PYTHONPATH=. python3 -m pytest -q --disable-warnings` from the pinned
`deps/python-keepkey` directory. The Bitcoin-only image
`sha256:12d356b3912a0e7f76923db50368ee66e979fed3935174b6084726090a8f99db`
runs the same 21-case set: **21 skipped** because Zcash messages are absent in
that product. The saved log is
`/private/tmp/kk-fw-715-p05-evidence/host-bitcoin-only.log`, SHA-256
`69558acfa9f2db78c7e675202aa98bd28ed726637aaab47cec2462a46ae59eb0`.
Both images were built for P03 from the same candidate code and
pins. `git diff --name-only 614425a2a14d0113de251e7944118e47f31f5265..ad119fdd7`
lists only audit documentation/SOP, so their behavioral evidence carries;
the new document commit requires a fresh diff check before final review.

The existing high-bit regression drives the FVK handler. There is no matching
high-bit host regression for the other two resolver callers in the inspected
companion tests. Their shared call path is source evidence, not three executed
handler regressions. Physical confirmation/OLED behavior, signed-device
upgrade, and exact later workflow CI remain separate release gates. A final
report/PDF, complete PR inventory and local preflight are still required
before any external review request under the SOP.
