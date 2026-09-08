# Cosmos-family alpha audit fixes

Audited at `ed65a0ce9bbfd06d58a30a834f5245e86310a794`.

## Fixed

- Added fail-closed returns after BIP32 path formatting failures in Cosmos,
  Osmosis, THORChain, and MAYAChain `GetAddress` handlers. These failures no
  longer continue to an empty-path confirmation or send a second address
  response.
- Added THORChain and MAYAChain final-signing disclosure of the signed fee and
  gas. Fees are formatted as RUNE (8 decimals) and CACAO (10 decimals);
  formatting failure aborts signing.
- Validated Osmosis IBC channel/port identifiers and canonical uint64 revision
  fields before display/signing, and escaped those values in the sign-doc as
  defence in depth. Regressions reject quote injection and leading-zero
  revisions.
- Hardened generic Tendermint sign-doc construction: fee denom, message type
  prefix, and message denom are validated and emitted through JSON escaping.
  Regression tests reject injected denom/prefix values.
- Made THORChain memo operation matching exact and case-insensitive. An
  unknown lowercase type such as `secure-` now returns UNPARSED and is raw
  paged rather than being labelled a swap.
- Deleted the uncalled MAYA structured memo parser, its public declaration, and
  its parser-only tests. Production MAYA signing already raw-pages every memo.
  `mayachain.c` now directly includes `messages-mayachain.pb.h` rather than
  relying on the deleted parser's transitive include.

## Central follow-up owned by root

MAYA/THOR/Osmosis private signing sessions survive normal central teardown on
the audited SHA. Added four existing-suite regressions (generic Tendermint,
Osmosis, THORChain, MAYAChain) that begin a session and assert it is cleared by
both `session_clear(false)` and `session_clear(true)`. They require the root's
central abort-session implementation and are expected to fail before it lands.

## Validation prepared

- `/opt/homebrew/opt/llvm@20/bin/clang-format --style=file --dry-run --Werror`
  passes for all touched source and test files.
- `git diff --check` passes.
- Shared builds were not run, per serialized build ownership. Run the root's
  firmware unit command after the central teardown patch, then filter the
  `Cosmos.*`, `Osmosis.*`, `Thorchain.*`, and `Mayachain.*` suites if diagnosis
  is needed.
