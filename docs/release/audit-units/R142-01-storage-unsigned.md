# R142-01: decode persisted integers as unsigned bytes

Status: staged; full candidate validation pending. This carries an existing
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
| 7.15 `a56fb3e88` | Present | Pending replay and storage-version interaction checks |

No Copilot request is part of this internal unit. No product or develop merge
is implied by staging it.
