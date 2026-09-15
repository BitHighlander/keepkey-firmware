# Non-runtime coverage audit: PRs 755 and 756

Read-only independent Astra pass on 2026-09-13, following ASTRA-AUDIT-SOP.md. No repository edits, GitHub replies, push, or Copilot request. Original runtime audit is recorded separately in /tmp/715-runtime-audit-report.md.

Frozen pairs:
- #755 actual base audit/7143-p03-pending-version-lock, 0f64f80323813e107c25b838d137cc0e65417d79 -> 18606c1a04b6740142b7313a59f47596542eec79.
- #756 actual base audit/715-p03-pending-version-lock, 06b1d249ada75b53d06cb5b7f27512fd276ef83c -> 4921cf913521aa5128f3818828cd049f34b90f49.
- Follow-up snapshots inspected for disposition: #762 1425de920, #763 cd60df966. Parent is changing these, so this report does not certify later heads.
- Current original-PR bodies read through gh on 2026-09-13; snapshots /tmp/715-nonruntime-evidence/pr755.json and pr756.json.

## Confirmed findings

| ID | Severity/location | Trigger and consequence | Evidence/disposition |
|---|---|---|---|
| NR-01 | P2, both .github/workflows/ci.yml: #755 lines 287/346/531/703 and 1037; #756 404/477/715/892 and 1279 | workflow_dispatch publish_emulator=true with successful builds/tests but failed static-analysis (or 7.15 crypto-tests) still permits Docker publication. Removing early job dependencies broke transitive publication prerequisites. | Parsed exact workflow DAG: publish-emulator does not depend transitively on static-analysis or ci-gate on either line; 7.15 additionally bypasses crypto-tests and generate-test-report. Whole ci-gate itself remains red, but publisher ignores it. Present at both follow-up snapshots. Parent informed; require ci-gate in publisher needs. No actual publish attempted. |
| NR-02 | P2 security explanation, both docs/dice-vs-coldcard.md:40-44 | Claims seeing device entropy lets host choose external entropy to obtain any seed it wants. Misstates the exploit and SHA256 preimage resistance. | For SHA256(internal||external), disclosure lets a host compute the resulting seed; arbitrary chosen seed still requires a preimage search. Replace with resulting-seed knowledge, qualifying dice mixing as appropriate. Parent informed. |
| NR-03 | Release-claim correction, both combined receipts and both PR Acceptance footers; 7.15 receipt:141-145 | Historical claims are read as current: 'this commit's parent', documentation-only final commit, no unresolved finding / no Copilot request. Follow-up banners acknowledge new runtime changes and open blockers but historical body lacks consistent boundaries. | Label historical certification sections with exact original validated SHA and run, and qualify all no-open/no-review statements. Existing top banners correctly deny readiness, so this is inconsistent documentation rather than evidence of release authorization. Parent informed. |
| NR-04 | P3 test-evidence labeling, #755 receipt:62 / #756 receipt:72 | Calls merged JUnit totals 'Host results', overstating host-only coverage. | Downloaded artifacts show 7143 aggregate1011=786pass225skip; host pytest759=534pass225skip, dylib4pass, native248pass. 715 aggregate1342=1305pass37skip; host pytest759=722pass37skip, dylib5pass, native578pass. Rename aggregate totals. Parent informed. |
| NR-05 | P3, both docs/dice-vs-coldcard.md:9,18,24,40 and categorical verification passages | Incorrect message field, mandatory-dice claim, and one-mode-only verification. | Actual field is EntropyAck.entropy, not ResetDevice.external_entropy. Current Coldcard standard setup permits dice OR coin flips OR timed keys; dice themselves are not mandatory. Both dice-only and mixed modes can be verified, as later document paragraphs already explain. DiceEntropy.md's exclusive dice-only-verifier wording is likewise too broad. |
| NR-06 | P3, #756 PR second-pass text | Says Eleven fixes but supplies ten bullets; 'fixed upstream' Hive wording may imply merged. | Receipt has corrected Ten. Python PR223 remains open/unmerged; pin deliberately tracks its review branch. Count ten and identify review-branch fix. |

Known power-loss P1 and persistent boot-marker failure remain OPEN release blockers. No new P1 identified in this non-runtime pass. No clean/release-ready conclusion is justified.

## Exact changed-file coverage

Each entry below was read against its own actual-base diff, with surrounding code or evidence where relevant. Shared paths were checked on both snapshots rather than assuming parity.

#755 (12 paths):
- .github/workflows/ci.yml — all changed jobs and dependency graph; NR-01; existing build-exit propagation follow-up acknowledged.
- .github/workflows/release.yml — separate bitcoin-only reproduction instructions, variant flag and artifact selection; no new confirmed issue.
- .gitmodules — protocol branch alignment independently checked upstream.
- deps/python-keepkey — new gitlink resolves to canonical review branch; receipt matches.
- docs/DiceEntropy.md — derivation, removed internal-entropy UI, host separation, verification limitations; categorical caveat NR-05.
- docs/dice-vs-coldcard.md — full comparison and proposed protocol extension; NR-02/05.
- docs/release/7.14.3-COMBINED-CANDIDATE.md — every claim read; run/artifact/pins checked; NR-03/04.
- docs/release/audit-units/full-diff-audit-20260912.md — all rows read; 21 fixed/2 refuted/23 triaged counts independently match sections. Prior-review multiplicity cannot be independently authenticated.
- docs/release/audit-units/scope-repair.md — restored storage/shared-memory baseline, bootloader-boundary withdrawal and open durability finding consistent with code/scope.
- docs/security/7.14.3-bitcoin-only-dice-audit-sop.md — changed gate language and withdrawal; no new issue.
- scripts/emulator/capture-dice-flow.py — removed obsolete reset argument/screen matches runtime; full script read, UDP-only wipe understood; not executed.
- tools/firmware/keepkey.ld — 16KiB runtime SRAM link assertion matches intended floor; physical stack sufficiency not established by assertion.

#756 (13 paths):
- .github/workflows/ci.yml — all changed jobs and dependency graph; NR-01. Shared-library publisher already requires ci-gate, manual image publisher omitted it.
- .gitmodules — both protocol and Python review branches independently checked upstream.
- deps/python-keepkey — exact PR223 review head pin verified, pending canonical merge explicit.
- docs/DiceEntropy.md — full changed text; NR-05.
- docs/dice-vs-coldcard.md — full comparison/proposal; NR-02/05.
- docs/release/7.15-COMBINED-CANDIDATE.md — full text, pins, exact historical CI/PDF binding; NR-03/04.
- docs/release/audit-units/full-diff-audit-20260912.md — all rows read; 78 fixed/11 refuted/77 triaged counts match sections. Prior model vote history not independently authenticated.
- docs/release/audit-units/scope-repair.md — withdrawal and restored baseline agree with scope.
- docs/security/clearsign-provider-tier.md — priority-fee and schema companion policy read against parser/schema behavior; runtime audit rejects price companion on opaque schema paths in follow-up.
- scripts/emulator/capture-dice-flow.py — full script and changed reset flow checked; not executed.
- scripts/generate-test-report.py — full wrapper, required native inputs, required controls, screenshot completeness/hashes, both ARM manifests, PDF/generator binding examined; nine meaningful fixture checks pass.
- tools/merge_direction_gate.py — complete read and before/after read-failure tests in prior runtime pass; confirmed ls-tree/show fix in 4aec28fca.
- tools/merge_symbol_gate.py — full scanner read, path anchoring and fatal read errors checked; run from /tmp reports zero real/test regressions and exits0. Heuristic scanner is not semantic proof of all guards.

Current #755 and #756 PR descriptions: full bodies reviewed; scope/known blocker banners correctly deny approval; NR-03/06 qualify history. Their detailed runtime claims rely on the completed runtime audits; the claimed historical three-reviewer votes were not independently reconstructable from repository evidence.

## Independent verification

- Historical successful CI runs confirmed via GitHub API:
  - https://github.com/BitHighlander/keepkey-firmware/actions/runs/34709138604 head f19b9d339915c8a9cc26335232109a12243fdaf7.
  - https://github.com/BitHighlander/keepkey-firmware/actions/runs/34709140171 head ad68841a5e20fb1683da1697b851ed859ef3b845.
- Each historical run-to-original-PR diff contains only the two receipt/ledger docs. Therefore original code equivalence is valid; current runtime follow-ups still need exact-head CI. Historical documentation commits c115b5bcc and271759d1b also contain only those docs.
- Downloaded report artifacts to /tmp/715-nonruntime-evidence/{7143,715}. Actual PDF and merged-JUnit SHA256 match sidecars/manifests on both. PDF hashes:7143 7681691bb00aaa6812ad30fb43ddfa4c6a57e66ca426ef05708fa9b075e9bbc0;715 03b1db87c7e6127a4e3e2f8f224808382ee80c66f0ef6c7792d48dd04852b28c. OLED manifest counts389/1167 match receipt; individual PNG/ARM binaries were not downloaded or independently rehashed in this pass.
- Nine report-wrapper controls: accept nonempty native suites; reject missing/zero-case native suite; accept all required passing cases; reject missing required case and errors; accept both correctly bound ARM fixtures; reject wrong firmware SHA and corrupted binary. All pass against original #756 script.
- merge_symbol_gate launched from wrong cwd /tmp exits0 with0 real and0 test regressions, demonstrating repository anchoring.
- All seven receipt gitlinks match each tree. device-protocol8545cd5 is contained in up/release-protocol (ahead12/behind0); 7143 Python7f538a95f00fdea59879ceab1a684762fe408411 equals reconcile/upstream-sync;715 Python6a85668736d7d4ecbb5dddf9478be65074a31154 equals fix/hive-wire-asset-symbols and PR223 head. PR223 open/unmerged.
- Primary Coldcard status and verification docs confirm standard setup alternatives and mixed-mode offline verification: https://coldcard.com/security/status and https://coldcard.com/docs/verifying-dice-roll-math/. Current version claims5.6.2/1.5.2Q match official status. Full vendor incident forensic attribution (including exact72-bit estimate) is not independently audited here.

## Remaining gaps / owner

Release owner/integrator must fix/disposition NR-01..06, validate any resulting head, and preserve open power-loss/persistent-marker blockers. This pass does not rerun Docker publication, ARM builds, full/BTC variants, hardware screens, signed upgrade, power-cut storage, RNG hardware, or reset/wipe emulator capture. Historical model-review provenance and individual historical OLED/ARM binary hashes remain unverified beyond downloaded manifest/PDF bindings. No changed non-runtime file from the original two diffs remains unassigned in this pass. Current follow-up-only new files belong to the parent/other reviewers and are not silently counted as full coverage here.

## Integrator disposition after this read-only pass

NR-01 is corrected on both follow-up branches by making manual emulator publication depend on `ci-gate`. NR-02 and NR-05 are corrected in both dice documents: the protocol field is `EntropyAck.entropy`, Coldcard permits dice/coins/keys as alternatives, both dice-only and mixed modes can be independently checked, and an observed seed input does not grant an arbitrary SHA-256 target preimage. NR-03 and NR-04 are corrected in both historical receipts and both PR descriptions; the aggregate JUnit totals are labeled combined native/host/dylib. NR-06 is corrected in PR #756's description (ten second-pass entries and the unmerged python-keepkey #223 branch). The release blockers and exact-head CI requirement remain open.
