# 7.14.3 and 7.15 candidate re-audit handoff — 2026-09-13

Status: **re-audit found additional work; neither candidate is ready for another Copilot
review, a `develop` merge, or release approval.** This document is the current
handoff for independent Astra review. Follow
[ASTRA-AUDIT-SOP.md](ASTRA-AUDIT-SOP.md) and the candidate's own release ledger.

| Candidate | Actual PR base | Frozen candidate head | Exact-head non-publishing CI |
| --- | --- | --- | --- |
| [7.14.3 #755](https://github.com/BitHighlander/keepkey-firmware/pull/755) | `audit/7143-p03-pending-version-lock` `0f64f80323813e107c25b838d137cc0e65417d79` | `efba271d2954a9b64db88b5ff8c3f92a6c7b1901` | [run 34798104808](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34798104808), success at this SHA |
| [7.15 #756](https://github.com/BitHighlander/keepkey-firmware/pull/756) | `audit/715-p03-pending-version-lock` `06b1d249ada75b53d06cb5b7f27512fd276ef83c` | `d7d0525e4c43e7464493a90a064505e16ec408fb` | [run 34798387842](https://github.com/BitHighlander/keepkey-firmware/actions/runs/34798387842), success at this SHA |

The previous Copilot review IDs were `5193039090` on #755 and `5193037080`
on #756. Both reviewed older heads (`18606c1a...` and `4921cf91...`), not the
frozen merge heads above. The reviewed findings, replies and local tests are
tracked in each candidate's `docs/release/audit-units/copilot-followup-20260913.md`
and `nonruntime-followup-20260913.md`. The six remediated inline threads on
#755 and five on #756 were resolved after exact-head CI. Two #755 inline
threads remain open: [erase-before-replacement power loss](https://github.com/BitHighlander/keepkey-firmware/pull/755#discussion_r4001507759)
and [boot-protection marker failure](https://github.com/BitHighlander/keepkey-firmware/pull/755#discussion_r4001507766).
The same storage behavior applies to #756 even though those are not its inline
threads. Do not mark a line clean by counting only its own open threads.

## Unclosed safety claims

1. Storage erases the active sector before a replacement is durably verified.
   A power cut can leave no recoverable wallet record. This is a release blocker
   on both lines; a successful ordinary commit/reload test does not close it.
2. A persistent protection-marker programming/readback fault can leave the
   currently active wallet sector readable in firmware while the installed
   bootloader wipes storage on the next boot. The bounded retry and readback
   fix closes transient fault behavior only. Verify the installed bootloader's
   actual policy and the next-boot consequence. This is separately release
   blocking on both lines.

The earlier scope repair explicitly excluded a storage durability redesign.
Keep these blockers open until a separately scoped, bootloader-compatible
transaction/recovery fix has power-cut and persistent-fault evidence on device,
or the release owner decides to hold the candidates. Do not silently waive
either through model consensus or a green CI badge.

## Independent Astra assignments

Use a fresh `gpt-6-astra` high-reasoning context for each bounded pass. Compare
each PR against its **actual base**. Read adjacent unchanged code and the
installed bootloader where needed. Return severity, changed file/line, reachable
trigger, consequence, proof, and verification; label prior findings, new
findings, and gaps separately.

| Pass | Challenge to resolve |
| --- | --- |
| Storage and boot | Reproduce both open next-boot failures; search all migration, sector-selection and marker failure paths for further wallet loss; specify a compatible recovery invariant and physical fault matrix. |
| Runtime and consent | Challenge signing/display equivalence, chain parsers, protocol pins and release carry-forward on both diffs. Test adversarial inputs against what a human sees and what is actually signed. |
| Evidence and claims | Reconcile every changed runtime/test/CI/doc/submodule file, host pin and PR claim; confirm exact-head run jobs and skips, ARM/bitcoin-only/SRAM evidence, and both lines' distinct behavior. |

The independent runtime pass found two P2s on #756:

- `lib/firmware/fsm_msg_solana.h:208` calls an ATA-derived destination
  **“Token account of <wallet>”**. Legacy SPL Token can reassign an ATA's
  controlling authority without changing its address. The display can
  therefore falsely assure ownership on a `TransferChecked` to a reassigned
  ATA. Remove the ownership assertion or qualify it as address derivation;
  add a screen-level regression. This is new relative to #756's base.
- `lib/firmware/fsm.c:301` still sends unmapped host messages through
  `fsm_abort_workflows()`, which clears an armed recovery/setup ceremony. #755
  narrowed this to signing-only abort and has a regression test. Carry that
  behavior and test forward to #756, including the Bitcoin-only recovery path.
  This predates #756's base, but is a missing 7.14.3-to-7.15 fix.

The storage pass reconfirmed both wallet-loss blockers. It also flagged a
third path: if the old sector erase fails while its magic survives,
first-magic active selection can cause `storage_protect_off()` to erase the
newly verified sector, then report a successful marker write beside the old
record. The erase primitive returns `void`, so the caller cannot detect this
from its return value. A temporary emulator fault-injection hook on the 7.15
head made the first erase of active sector 1 fail; a native test forced that
sector ordering, called `storage_commit()`, and failed because the replacement
sector no longer contained `stor` (`/private/tmp/kk-storage-fault-proof.log`).
The temporary hook/test were restored and are not in #764. This confirms a
silent update-loss path in the emulator model; physical flash fault and
next-boot evidence are still required, and the same 7.14.3 path needs its own
test. Treat it as an additional open storage release blocker.

The integrator must independently verify P1/P2 reports and maintain a
changed-file coverage matrix. Current gaps include physical power-cut and
persistent-marker next-boot proof, physical OLED/device signing and recovery,
and any host/variant checks not demonstrably present in the linked exact-head
runs. Record missing evidence rather than inferring it from emulator or native
tests. Exact CI success is a build/test receipt, not wallet-durability proof.

## Gate for the next Copilot review

Close or technically refute each actionable prior and new finding on **both**
release lines; preserve any deferred thread open. Require full assigned-file
and PR-claim coverage, exact new-head CI on every changed candidate, reviewed
dependency pins, and the storage/physical gates above. Then freeze a new head,
record the old review IDs, request Copilot **once** for that head, verify its
`review_requested` event and returned review `commit_id`, and ingest both inline
and body findings. If any gate remains open, do not spend a new Copilot request.
Poll deliberately, following the SOP's quota and three-request limits.

## Re-audit result ledger

| Pass | Frozen heads reviewed | Result / evidence | Remaining gap |
| --- | --- | --- | --- |
| Storage and boot | Both frozen heads | Both known wallet-loss paths reconfirmed in source; old-sector erase fault reproduced by temporary 7.15 emulator injection | Three storage blockers; physical fault/next-boot evidence and 7.14.3 reproduction |
| Runtime and consent | Both frozen heads | Two #756 P2s above; native 7.15 chain test subset 155/155 passed | Fix and verify #756; full changed-file coverage still required |
| Evidence and claims | Both frozen heads | Exact-head CI verified; four ARM variant ZIPs and 92 manifest file hashes checked | Physical gates and explicit CI skips remain |

### Follow-up round, 2026-09-13

The two confirmed 7.15 P2 findings are addressed in draft
[#764](https://github.com/BitHighlander/keepkey-firmware/pull/764), head
`b805e7ca79187ce14027aabc3fb47709e1a457f0`. Its Solana confirmation
states that a wallet address derives the destination ATA but the current
token-account owner is **not verified**, while retaining the signed amount and
destination. The 7.14.3 transport-abort fix and regression were carried into
7.15. Focused native FSM/Solana tests passed (64/64), followed by 441/441
Mac-safe firmware tests on the combined code; hosted exact-head CI is pending.

Independent review then found that both lines kept recovery data but hid the
substitution cipher after an unrelated transport failure. A redraw of the
**same** mapping and a real recovery-screen regression are in #764 and draft
[#765](https://github.com/BitHighlander/keepkey-firmware/pull/765), head
`e69c3f70b72e33716bddae96d4a792bfa979b442`. The test now renders the
cipher animation and compares the entire one-byte-per-pixel framebuffer; an
earlier partial-buffer version was rejected by the second Astra pass. The
corrected 7.15 focused test passes locally. The 7.14.3 port's two-argument
display API was checked and fixed before its latest push. Its isolated native
build and focused recovery/FSM tests pass (2/2), as do 174/174 Mac-safe
firmware tests. #765 still needs exact-head CI and physical OLED verification.

A fresh Astra pass of both final patch heads found no remaining P1/P2 in this
focused diff. It verified that the test advances the 300 ms cipher animation,
checks a nonblank cipher area, and compares the full framebuffer after mixed
signer cleanup. This is source review, not physical screen evidence; partial
words, autocomplete and prior-word display are outside this regression.

Neither draft is merged into its candidate. CI on a fix branch is not the
post-merge candidate receipt. Merge only after green fix-head CI and review,
then dispatch non-publishing CI on each new `audit/*` merge head. The three
storage blockers, 7.14.3 erase-failure reproduction,
full changed-file coverage reconciliation, and physical gates remain open.

The evidence pass checked all four ARM variant ZIPs against their manifests:
92 file hashes matched. Both report-bundle PDF and merged-JUnit hashes also
matched. #755 reports 1,021 cases (796 pass, 225 skip) and 389 OLED frames;
#756 reports 1,353 (1,316 pass, 37 skip) and 1,167 frames. Separate
Bitcoin-only results exist but are omitted from those merged totals. The
Python pins match the open review heads of upstream PRs #197 (`7f538a95`)
and #223 (`6a856687`); the shared protocol pin `8545cd5b` resolves upstream.
Both lines still skip five host boot/version tests because the host container
has no owned `kkemu`; #756 also skips two power-cycle tests. These skips do
not satisfy physical-device gates.

The frozen PR diffs contain 56 files on #755 and 74 on #756. Earlier runtime
and non-runtime coverage ledgers were written before the follow-up merge heads,
so reconcile the added test seams, CMake/harness files and receipts against
these complete file lists. No whole-head coverage claim is established yet.

Evidence reconciliation also found stale wording in both candidate ledgers:
the follow-up files say all original inline threads are unresolved and old-head
CI is pending. Those sentences describe the pre-merge state; the live state is
the two open #755 storage threads and green merge-head runs above. Candidate
PR titles have been corrected to say storage blockers are open. Update the
branch ledgers with new exact-head receipts when the next fix changes either
head; do not overwrite historical receipts without labeling them.
