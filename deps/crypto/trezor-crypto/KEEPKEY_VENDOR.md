# KeepKey vendored trezor-crypto

This directory is a direct, in-tree firmware dependency. It replaces the
`deps/crypto/trezor-firmware` submodule so that a KeepKey release no longer
depends on an unrelated Trezor monorepo fork.

## Provenance

- Previous RC18 crypto pin: `keepkey/trezor-firmware@0837875b9f5ce29f5d29f2a8ad3798787bd25b61`
- Vendoring baseline: `keepkey/trezor-firmware@56f404e452bc7738cd3b3e14454dfecb25c083bf`
- Upstream audit reference: `trezor/trezor-firmware@90e07df6c8b85ff3dc41f502de9dfff21493671b`
- Audit date: 2026-07-25
- License: MIT; see `LICENSE`

The vendoring baseline contains the KeepKey AES-small-tables and
Orchard/Pallas work. The source in this directory additionally contains the
security backports and KeepKey adaptations recorded in
`SECURITY_BACKPORTS.md`.

The complete `crypto/` subtree is retained, including its tests. No Trezor
Core, Legacy firmware, Python client, storage implementation, CI, or other
monorepo component is vendored.

## Updating

Do not merge the current Trezor monorepo into this directory for version
optics. Audit crypto changes explicitly:

1. Fetch `https://github.com/trezor/trezor-firmware.git`.
2. Review `git log --no-merges <last-audited-sha>..upstream/main -- crypto`.
3. Classify each correctness or security change for the KeepKey build and
   document the decision in `SECURITY_BACKPORTS.md`.
4. Apply applicable changes to an isolated crypto worktree, preserving
   upstream commit IDs in commit messages.
5. Run the standalone optimized and sanitizer suites below.
6. Replace this directory from the tested worktree and run both full firmware
   variants before opening a PR.

The upstream monorepo had diverged by 7,996 commits and 5,494 files at this
audit point. A mechanical merge was possible but was not treated as a
security review.

## Standalone verification

On macOS with Homebrew `check` installed:

```sh
make clean
make VALGRIND=0 \
  OPTFLAGS='-O3 -g -I/opt/homebrew/include -Wno-error=unterminated-string-initialization' \
  tests/test_check
./tests/test_check
```

ASan and UBSan:

```sh
make clean
make CC='clang -fsanitize=address,undefined' VALGRIND=0 \
  OPTFLAGS='-O1 -g -fno-omit-frame-pointer -I/opt/homebrew/include -Wno-error=unterminated-string-initialization -Wno-error=deprecated-declarations' \
  tests/test_check
ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./tests/test_check
```

The vendoring audit passed 158 checks in both configurations.
