# Independent reconciliation review: python-keepkey

Date: 2026-09-07

Reviewed immutable merge baseline `eaae16db64ae02d2f84c15bd65bb1276f0d7d8d6`
(parents `999e776` master and `d0b6669` pinned/Hive), follow-up protocol-pin
commit `6f19e7a`, and review-remediation commit `c403e86`. The review was bounded
to master-to-candidate changes in the client, CI workflows, protobuf bindings,
EIP-712 helpers, and security tests, plus preservation and the two STEEM wire
assertions. No firmware or protocol repository was modified by this review.

## Verdict

The reconciliation preserves the reviewed master behavior and the pinned
security changes. Two concrete candidate defects are fixed in `c403e86`. One
ordered integration dependency remains before publication: all current-firmware
CI lanes must be repinned from firmware `e07a95e7...` to the forthcoming firmware
commit that contains the matching multidimensional EIP-712 traversal fix. The
new device-driven test in `c403e86` makes that dependency observable.

The device-protocol gitlink at `bee6cdd624905d6b5bcc54a05fc3deb24242483d`
is correct. The prior directional report stated its ancestry backwards: the
actual count for `bee6cdd...f54f0a7` is `5 0`, and `f54f0a7` is an ancestor of
`bee6cdd`. Thus `bee6cdd` contains `f54f0a7` plus five commits; it is not five
commits behind it.

## Finding 1: ABI validation disappeared under optimized Python (fixed)

Severity: high for the integrity of clear-sign fixtures and catalog-generated
calldata; reachable whenever this helper is run with `python -O`.

At baseline `eaae16d`, `keepkeylib/clearsign_abi.py` used `assert` for address
length, argument count, unsigned range, signed range, and fixed-bytes length.
Python removes all of those checks under `-O`. A concrete trace was:

1. A catalog/test calls `build_calldata()`, which calls `encode_static_args()`.
2. A value such as `uint8(256)` or `int8(128)` reaches an assertion-based range
   check.
3. Under optimized Python the check does not execute.
4. The helper emits a plausible 32-byte word whose value is outside the declared
   Solidity type. Wrong-length address and `bytesN` inputs similarly alter the
   encoded layout, and unequal argument counts are silently truncated by `zip`.

This was also a bad-test condition: `tests/test_clearsign_abi.py` expected
`AssertionError`, so it codified checks that Python may legally remove.

Root cause: `assert` was used for input validation in a deterministic calldata
builder. This contradicted the candidate's own `signed_metadata.py` approach,
which uses explicit exceptions so validation survives optimization.

Remediation in `c403e86`:

- `keepkeylib/clearsign_abi.py:41-45,72-77,88-108,118-133` now raises
  `ValueError` for every invalid address/count/range/fixed-bytes condition.
- `tests/test_clearsign_abi.py:18-56` expects `ValueError` and launches the real
  interpreter with `-O`, checking all five validation classes.

Regression strategy and result: `python3 -m pytest tests/test_clearsign_abi.py
-q` passes 12/12, including the optimized-interpreter subprocess.

## Finding 2: CircleCI claimed firmware-unit was removed although Compose still ran it (fixed)

Severity: medium CI correctness/diagnostic defect. This was not a signing-path
security defect, but it could misclassify or obscure the suite that failed.

At `eaae16d`, `.circleci/config.yml:55` invoked `docker-compose up --build
python-keepkey`. The pinned firmware's `scripts/emulator/docker-compose.yml:34-38`
declares `python-keepkey` dependent on `firmware-unit` with
`service_completed_successfully`. Compose starts dependencies by default, so the
firmware suite continued to execute and gate startup. The candidate comments at
old lines 63-83 said that suite was dropped, and only the Python status was
copied/checked. Removing the explicit first `up firmware-unit` did not remove the
dependency.

Root cause: the workflow was edited as if service selection disabled Compose
dependencies, while the pinned Compose graph still expressed the dependency.

Remediation in `c403e86`: `.circleci/config.yml:55-75` now truthfully states that
both suites run, copies both report trees, requires both status files, and fails
if either status is absent or nonzero. This preserves the actual intended
dependency and its gate.

Regression strategy and result: the YAML parses successfully with `yaml.safe_load`;
the command/status flow was checked against the pinned Compose dependency. A live
Circle remote-Docker run remains CI-only.

## Finding 3: corrected host array order is incompatible with pinned e07 firmware (open, ordered)

Severity: medium compatibility blocker for multidimensional structured EIP-712.
Single-dimensional and non-array structured signing are unaffected.

The Python correction is semantically right: `keepkeylib/eip712_stream.py:44-52`
consumes Solidity array dimensions right-to-left. Therefore
`int16[2][4]` means an outer list of 4 lists, each containing 2 integers.
`build_struct_ack()` retains the lexical descriptor `[2, 4]`, as required for the
type spelling sent over the wire.

The currently pinned firmware `e07a95e7...` disagrees:

- its `lib/firmware/eip712_stream.c:932` sets the outer declared dimension from
  `array_levels[0]`, so it expects 2 when the host returns outer length 4;
- its inner-array path at line 721 sets `pending_declared_dim = 0`, discarding
  fixed inner dimensions.

The result is deterministic: the device requests the array length at path
`[1,0]`; the corrected host returns 4; e07 compares 4 to 2 and emits failure
before any signature. The baseline's multidimensional regression at
`tests/test_msg_eip712_streaming.py:78-123` only exercised host path resolution,
so it could not expose this cross-repository mismatch.

Current alpha firmware contains the matching implementation:
`lib/firmware/eip712_stream.c:668-670` selects
`elem_dims[levels_total - 1 - level_index]`, lines 735-738 retain and validate
inner dimensions, and lines 971-979 apply the same rule to the outer dimension.

Partial remediation in `c403e86`:
`tests/test_msg_eip712_streaming.py:215-236` adds a real device-driven asymmetric
`int16[2][4]` walk. Two dimensions fit the firmware's documented frame bound
(`EIP712_MAX_DEPTH == 3`) while still distinguishing outer 4 from inner 2.

Required ordered remediation: after the current firmware fixes are committed and
published, replace `e07a95e7d069553c273b24552c9bc436f60f5d91` at:

- `.github/workflows/ci.yml:134` (current full-feature integration),
- `.github/workflows/ci.yml:553` (current bitcoin-only integration), and
- `.circleci/config.yml:35` (Circle emulator/firmware-unit lane).

Then run the new device test against that exact pin, both current integration
jobs, and the Circle suite. Do not repin the RC18 compatibility lane; it is
supposed to exercise the release target and the 7.16 test self-skips there.

## Protocol pin and generated binding

`6f19e7a` changes only the Python `device-protocol` gitlink from `f54f0a7` to
`bee6cdd`. Independent local graph checks show:

- `git rev-list --left-right --count bee6cdd...f54f0a7` -> `5 0`;
- `git merge-base --is-ancestor f54f0a7 bee6cdd` -> success;
- the five additional commits change only `.github/workflows/build-and-publish.yml`,
  `package.json`, `package-lock.json`, and `test.js`;
- a restricted diff of `*.proto` and `*.options` is empty.

The Solana schema at both protocol commits already declares optional bytes field
13 (`clearsign_certificate`) with max size 139. The candidate generated binding
exposes field 13 as optional bytes, and
`tests/test_message_signing_protocol_bindings.py:35-57` round-trips a full
139-byte certificate. No protobuf wire incompatibility was found.

`.gitmodules` remains on the organization URL
`https://github.com/keepkey/device-protocol.git`. The operator separately ran
`gh api repos/keepkey/device-protocol/commits/bee6cdd624905d6b5bcc54a05fc3deb24242483d
--jq .sha` and received the exact SHA, proving the pinned object is served from
the declared organization URL. A personal-fork URL redirect is therefore neither
needed nor appropriate.

## Preservation and behavior checks

Tree identity: `git diff --exit-code eaae16d d0b6669` succeeds. The merge result
is byte-for-byte the pinned/Hive parent, so conflict resolution did not create a
third tree.

Path/definition preservation: comparing all tracked paths finds no master-only
path. An AST comparison over `keepkeylib/*.py` and `tests/*.py` finds one
master-only definition:
`TestMsgEip712Streaming.test_advanced_mode_gates_the_endpoint`. Its removal is
intentional and behaviorally replaced by
`test_advanced_mode_is_not_required_for_structured_review`: current structured
streaming validates, renders, and hashes the same values, while the separate
precomputed-hash/blind path remains AdvancedMode-gated. No other master test or
client definition was dropped.

Client hunks: the reviewed client changes preserve the existing request flow and
add fail-closed version gates for Thorchain/Osmosis legacy serializers, optional
Zcash account-only display construction, transparent-PCZT signature count/nonempty
validation, and a public settled OLED-capture helper for manual protocol tests.
No dropped client behavior was found in the bounded hunks.

Security tests: the candidate strengthens observable outcomes rather than merely
asserting response types. Reviewed examples recover Ethereum signatures over the
complete streamed calldata (`tests/test_msg_ethereum_signing_guards.py:216-247`),
prove a tail-only mutation changes captured layouts (lines 277-304), refuse
missing/empty Zcash transparent signatures, reject oversized multisig DER input,
assert bitcoin-only tests execute without skips, and initialize wallets before
display-disclosure comparisons. No security regression was found in these hunks.

## STEEM wire assertions

Both candidate assertions are correct and non-circular:

- `tests/test_msg_hive.py:356` parses the signed transfer asset as
  `(1000, 3, "STEEM")`.
- `tests/test_msg_hive.py:402` parses the account-create fee as
  `(3000, 3, "STEEM")`.

The Python helper at `keepkeylib/hive.py:17-32` passes the display symbol `HIVE`
unchanged in the request; it does not manufacture the asserted legacy wire text.
Firmware `lib/firmware/hive.c:917-928` maps display symbol `HIVE` to wire symbol
`STEEM` for transfer serialization, and lines 978-980 explicitly serialise the
account-create fee with `STEEM`. `_Reader.asset()` reads the actual device-emitted
signed bytes. The assertions therefore bind the legacy Hive wire format rather
than echoing a host helper constant.

## Local validation of c403e86

- `python3 -m pytest tests/test_clearsign_abi.py -q`: 12 passed.
- `PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python python3 -m pytest
  tests/test_msg_eip712_streaming.py::TestEip712StreamHelpers -q`: 3 passed
  (101 deprecation warnings from legacy generated protobuf code).
- `python3 -m py_compile` on the modified Python/test files: passed.
- `git diff --check`: passed.
- CircleCI YAML parse with `yaml.safe_load`: passed.
- Worktree after commit: clean.

The new device-driven EIP-712 test was not run locally because it requires the
emulator built from the unpublished fixed firmware. It is expected to fail on the
still-pinned e07 firmware for the concrete dimension-order trace above; that red
result is the purpose of the ordered repin requirement.
