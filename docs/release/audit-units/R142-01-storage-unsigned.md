# R142-01: decode persisted integers as unsigned bytes

Status: local storage contract passed; assembled product acceptance pending. This carries an existing
rehearsal fix to the current release product, not a new broad storage audit.

## Contract and provenance

- Product baseline: `cdde6888c2792cd9c673d0ff47f0cdb8069e08dc` (7.14.2).
- Source fix and round-trip regression: `ce21b4ac87d43f32197f91dec68876ac61ac3891`.
- Scope: `read_u32_le` and a V17 round-trip regression. No format, policy, KDF,
  dependency or product feature changes.
- Invariant: decode all four little-endian bytes without sign extension on either
  signed-char or unsigned-char targets. Absent secret flags remain absent.
- Existing defect: on signed-char targets, bytes `80 ff 80 12` decode incorrectly;
  flag byte `c0` also sign-extends into unrelated upper flag bits.
- Review: conversion through `const uint8_t*` makes each byte unsigned before
  widening and shifting; byte-wise access preserves unaligned-buffer support.

## Evidence and acceptance

An isolated C probe compiled the exact baseline and candidate helper with
`-Wall -Wextra -Werror`, under both `-fsigned-char` and `-funsigned-char`.
The baseline failed the signed-char vectors and passed unsigned-char; the
candidate passed both. This establishes the decoder regression, not complete
firmware correctness. The imported V17 regression exercises persisted public
integers and absent-secret flags through the actual storage writer and reader.

Required before acceptance: compile and run that firmware regression on this
candidate, assess relevant storage tests, and retain complete product checks as
an assembly gate. Earlier rehearsal results support provenance but do not count
as execution on this product candidate. ARM's char mode must not be assumed to
match the host; this change preserves already-correct unsigned-char behavior.

## Release applicability

| Product snapshot | Decoder defect | Delivery |
| --- | --- | --- |
| 7.14.2 `cdde6888c` | Present | This audit unit; not yet assembled into product |
| 7.14.3 `abe29d128` | Present | Pending replay and variant checks |
| 7.15 `a56fb3e88` | Already fixed equivalently | Preserve existing implementation; no duplicate code patch |

No Copilot request is part of this internal unit. No product or develop merge
is implied by staging it.

## Current execution receipt

Native AppleClang build succeeded with C++14, CMake legacy-policy compatibility,
`PB_NO_PACKED_STRUCTS=1` and the nanopb 0.3.9.4 generator command accommodation.
These are host build settings; production ARM validation remains separate.
All 20 `Storage.*` tests passed. Replacing only the decoder with the original
baseline implementation made the added V17 regression fail; restoring the fix
passed it. The extraction needed explicit C declarations for the two existing
private V17 functions in the test; no production API was changed.

Full firmware-unit: 77 passed, 3 failed out of 80. The same three failures
reproduce with the original decoder on this product and dependency configuration:
`Coins.TableSanity`, `Ethereum.TransformErc20RequiresCompleteCalldataForClearSigning`,
and `Ethereum.TransformErc20RequiresBothTokensResolvable`. Track these as R142-02
(token-table/fixture reconciliation), rather than expanding the decoder patch.
No assembled release acceptance is claimed until they are dispositioned and the
required product checks pass. Local logs are `/private/tmp/7142-unsigned-*.log`
and `/private/tmp/7142-baseline-three-tests.log`.

Fork audit PR: #641, targeting its actual predecessor `release/7.14.2`; targeting
current develop conflicted with later integrations. Product PRs still target
develop. This preserves the three-file audit diff and the release-specific base.
