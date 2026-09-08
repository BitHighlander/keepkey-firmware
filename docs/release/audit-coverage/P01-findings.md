# P01 build/dependency/release audit findings

Status: phase in progress. These are bounded findings, not a claim that every
P01 path or another phase has been reviewed.

| ID | Product | Disposition | Evidence / staged unit |
| --- | --- | --- | --- |
| P01-001 | 7.15 | Fixed and rechecked; integration pending | Empty/default manifest exits 0 and claims signed zero applications before; refuses after, valid unsigned fixture preserved. [#669](https://github.com/BitHighlander/keepkey-firmware/pull/669), `1a4bbdfe3` |
| P01-002 | 7.14.3 | Fixed and rechecked; integration pending | Actual selector emits two variant outputs while packaging consumed a nonexistent one. Complete/missing/duplicate/expired fixture rehearsal. [#670](https://github.com/BitHighlander/keepkey-firmware/pull/670), `747e800fa` |
| P01-003 | 7.14.2 / 7.14.3 | Fixed and rechecked; integration pending | Actual prepare step copies bootloader; hashes precede rename. Rehearsal now stages firmware only with matching final filenames and hashes. [#671](https://github.com/BitHighlander/keepkey-firmware/pull/671), `cc23d506d`; [#672](https://github.com/BitHighlander/keepkey-firmware/pull/672), `1d439b963` |
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

## Remaining release-workflow review

The 7.14.2/7.14.3 signing checklist still needs a precise signed-image manifest
regeneration disposition. 7.15 rebuilds release ARM artifacts instead of reusing
its audited CI binaries; review its source/build/evidence contract before deciding
whether this is an actionable gap. A shellcheck warning in its bootloader guard
also remains to be dispositioned. Dependency delta review and the rest of P01
remain pending. Do not automatically import the 7.15 workflow into older products.
