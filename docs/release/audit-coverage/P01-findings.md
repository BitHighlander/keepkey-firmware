# P01 build/dependency/release audit findings

Status: phase in progress. These are bounded findings, not a claim that every
P01 path or another phase has been reviewed.

| ID | Product | Disposition | Evidence / staged unit |
| --- | --- | --- | --- |
| P01-001 | 7.15 | Fixed and rechecked; integration pending | Empty/default manifest exits 0 and claims signed zero applications before; refuses after, valid unsigned fixture preserved. [#669](https://github.com/BitHighlander/keepkey-firmware/pull/669), `1a4bbdfe3` |
| P01-002 | 7.14.3 | Fixed and rechecked; integration pending | Actual selector emits two variant outputs while packaging consumed a nonexistent one. Complete/missing/duplicate/expired fixture rehearsal. [#670](https://github.com/BitHighlander/keepkey-firmware/pull/670), `747e800fa` |
| P01-003 | 7.14.2 / 7.14.3 | Fixed and rechecked; integration pending | Actual prepare step copies bootloader; hashes precede rename. Rehearsal now stages firmware only with matching final filenames and hashes. [#671](https://github.com/BitHighlander/keepkey-firmware/pull/671), `4646d69be`; [#672](https://github.com/BitHighlander/keepkey-firmware/pull/672), `2678b075c` |
| P01-004 | All three | Fixed and rechecked; integration pending | Required native suites must exist, parse and contain cases; 40 negative mutations refused. 7.15 also requires screenshot evidence and selection JUnit. [#673](https://github.com/BitHighlander/keepkey-firmware/pull/673), `d271cb0ec`; [#674](https://github.com/BitHighlander/keepkey-firmware/pull/674), `a67b7f792`; [#675](https://github.com/BitHighlander/keepkey-firmware/pull/675), `e43daa81d` |
| P01-005 | 7.14.2 | Static contract fixed; rebuilt validation pending | CI overrode the immutable Dockerfile base with mutable v15 tags. Pin every build consumer to the existing release digest. [#676](https://github.com/BitHighlander/keepkey-firmware/pull/676), `744dfe4e9`. |
| P01-006 | 7.15 | Fixed and rechecked; integration pending | Empty Bitcoin-only disassembly falsely passed. Real full/BTC artifacts still pass; empty, garbage, symbol-only, wrong-variant and missing-multiplier fixtures fail. [#677](https://github.com/BitHighlander/keepkey-firmware/pull/677), `8126b57e7`. |
| P01-R02 | 7.15 | Rejected; experimental change withdrawn | Actual firmware.xml already contains all 72 Zcash cases. Standalone CTest repeats those cases in another linkage; missing standalone XML is not absent test coverage. Inspect emitted cases before asserting a gap. |
| P01-R01 | 7.15 | Rejected as a current public-repository defect | Validate lacks actions:read, but GitHub expressly permits public workflow-run reads without that permission. The artifact-download job grants actions:read. Do not claim a reproduced permission failure or add a speculative blocker. |

P01-R01 sources: [workflow-run API](https://docs.github.com/en/rest/actions/workflow-runs#list-workflow-runs-for-a-repository)
and [workflow permission semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions).

## Repeatable local rehearsals

Run from the trusted firmware worktree being reviewed. Python 3 and PyYAML are
required. These scripts execute the reviewed workflow's local packaging/selector
code over synthetic inputs in temporary directories; they do not call GitHub,
create tags or publish releases. Darwin adapts only GNU stat's filesize spelling.

- `python3 /path/to/phase-scope/docs/release/rehearsals/release_packaging.py`
  covers 7.14.2 full and 7.14.3 full/Bitcoin-only packaging.
- `python3 /path/to/phase-scope/docs/release/rehearsals/artifact_routing_7143.py`
  exercises actual selection plus producer/job/matrix output bindings.
- `sh scripts/release/hash-manifest.sh --self-test` on the 7.15 P01 branch
  exercises missing/invalid inputs in both modes and valid unsigned output.
- `actionlint .github/workflows/release.yml` on the 7.14.2/7.14.3 phase branches.

- `python3 /path/to/phase-scope/docs/release/rehearsals/native_report_inputs.py CHECKOUT CI_NATIVE_XML_DIRECTORY`
  accepts real native artifacts and rejects missing/empty/malformed/no-case mutations.

## Remaining release-workflow review

The 7.14.2/7.14.3 checklist now requires three verified signatures and manifest
regeneration from final signed, versioned images; packaging hashes are explicitly
unsigned presign evidence. 7.15 rebuilds release ARM artifacts instead of reusing
its audited CI binaries; review its source/build/evidence contract before deciding
whether this is an actionable gap. A shellcheck warning in its bootloader guard
also remains to be dispositioned. Dependency delta review and the rest of P01
remain pending. Do not automatically import the 7.15 workflow into older products.
