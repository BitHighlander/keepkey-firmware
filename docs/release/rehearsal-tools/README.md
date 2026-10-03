# Rehearsal tools

Executable form of `docs/release/REHEARSAL-SOP.md` ("Dress rehearsal into fork develop") and of the pinning rule in
`docs/release/BRANCHING-SOP.md` ("One canonical branch per dependency, never split").

Needs: `gh` (authenticated), `git`, `python3`, a firmware clone at `$FW` (default `~/keepkey-toolchain/fw-fold`) with a
`fork` remote, and in each of `deps/python-keepkey` and `deps/device-protocol` a remote named `kk` pointing at the
`keepkey/*` upstream. Run with `bash`, not zsh.

| Tool | Use | When |
|---|---|---|
| `rehearsal-preflight.sh <ref>...` | Strict pin gate: the canonical upstream PRs are the only open ones from their branches and equal their branches' heads; every ref pins both heads exactly; `.gitmodules` is canonical. Exits non-zero on any split. `ALLOW_ANCESTOR=1` only for the upstream base release. | Step 0, before every merge, after every merge, on release branches |
| `repin-caps.sh <pyk-head> <dp-head>` | Example of bringing a chain of block branches (`caps/<block>`) to the canonical heads: merge the block below, then one pin commit staged with `update-index` (never `commit -a`). Adapt the branch names. | Step 0, when the canonical heads moved |
| `merge-blocks.sh [index]` | Merges the block PRs into fork `develop` one at a time with all gates, and writes the receipt. Index 0 is the base release PR. Stops on any red. Edit its `BLOCKS` list for the release. | Steps 2-3 |
| `cut-release-branches.sh` | Creates the two release branches from the 7.15 and 7.16 tip merges, only if their trees equal the verified stack tips. `ID=` sets the suffix. | Step 4 |
| `receipt-identity.sh [start-sha]` | Appends the identity table (merge, tree, parents, own diff, pins) to the receipt. | Step 6 |

Never edit a script while it is running. Rehearsal switch: repository variable `KK_CI_REHEARSAL` (`1` on, `0` off).
