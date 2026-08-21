# SRS — KeepKey Firmware 7.15.0

Software Requirements Specification, IEEE 830 (concise form).
Status: **draft against `alpha`**. Baseline `dda531024`.

---

## 1. Introduction

### 1.1 Purpose
Defines what 7.15.0 must do, what it must NOT do, and how each requirement is
verified. Audience: firmware, host (Vault/SDK), and release review.

### 1.2 Scope
7.15.0 is the first release carrying the clear-signing *provider* tier. It adds
context to what the device already shows. **It never removes a screen.**

Two products ship:

| Product | Contents |
|---|---|
| Regular (`full`) | Every supported chain, including Zcash shielded/Orchard |
| Bitcoin-only | Bitcoin only; non-Bitcoin coins and Zcash privacy compiled out |

There is no separate `zcash-privacy` artifact.

### 1.3 Definitions
- **Clear-signing** — rendering a transaction's meaning (protocol, amounts,
  recipient) instead of raw calldata.
- **Provider** — a third-party identity supplying decode context. **Not**
  KeepKey attestation.
- **Runtime signer** — a provider identity loaded this session, RAM-only.
- **Pinned signer** — a verification key compiled into firmware. **None exists
  in 7.15** and none may.
- **Blind sign** — signing bytes the device cannot describe.
- **AdvancedMode** — session-scoped opt-in policy; never a flash bit.

### 1.4 References
- `docs/security/clearsign-provider-tier.md` — the tier's own scope rules
- `docs/security/clearsign-key-delegation-roadmap.md` — phases 0–3
- `docs/security/7.15.0-rc18-release-shape.md` — the two-product decision
- `docs/release/DEFECTS-2026-08.md` — defect register
- `deps/python-keepkey/scripts/generate-test-report.py` — the atlas (`SECTIONS`)

---

## 2. Overall Description

### 2.1 Product perspective
A signing device whose only real output is **what the user sees before they
press the button**. Every requirement below is ultimately about that screen.

### 2.2 User characteristics
Assume a user who reads the screen and does not read the host. The device may
never rely on the host to tell the truth, and may never rely on the user knowing
what a selector or an ABI offset is.

### 2.3 Constraints
- **C-1** STM32F205: ≥16 KiB SRAM reserve between `_ebss` and `_stack`, enforced
  by a linker `ASSERT` and `tools/check_sram_budget.py`.
- **C-2** No bootloader changes in this release.
- **C-3** The device's `snprintf` is integer-only; no float conversions.
- **C-4** `confirm()` paginates a body over `BODY_ROWS = 3`; bytes outside
  `0x21..0x7e` render as 4-glyph `\xNN` escapes.
- **C-5** Firmware SKIPS unknown protobuf fields — it does not reject them. A
  host on an older protocol degrades silently, so gating must be host-side and
  fail closed.

### 2.4 Assumptions
Hosts are untrusted. Providers are untrusted-but-named. The user is the only
authority.

---

## 3. Specific Requirements

### 3.1 Clear-signing is additive — THE release invariant

**R-1.1** After a successful clear-sign decode from a runtime-loaded provider,
the baseline raw/unverified review SHALL still run.
*Verify:* atlas F1/F2. Measured — Aave `supply()` baseline is 3 screens; a
VERIFIED v1 decode is 10 screens with those 3 **byte-identical at the tail**;
v2 static schema is 13 with the same tail.

**R-1.2** A payload whose signature fails verification SHALL fall back to the
ordinary unverified review — neither refusing nor showing partial decoded info.
*Verify:* F3. Measured: 3 frames byte-identical to baseline.

**R-1.3** No runtime signer SHALL reach the suppression branch.
*Verify:* F4/F5. All four slots produce VERIFIED decodes still followed by the
full baseline; no slot verifies without a runtime load.

**R-1.4** The firmware SHALL contain no pinned provider key.
*Verify:* zero key bytes in `signed_metadata.c`. **This single property is what
separates 7.15 from 7.16.**

> **What the user sees.** With a provider loaded and a matching signed payload:
> the provider's alias and fingerprint, then decoded screens naming the
> protocol, amounts and recipient — and then *the same raw-data review they
> would have seen with no provider at all*. Nothing is taken away.

### 3.2 Provider trust is opt-in and dies on its own

**R-2.1** AdvancedMode SHALL be session state, never a flash bit.
*Verify:* atlas I1; `storage.c` ignores legacy bit 12 at four sites.

**R-2.2** Loaded identities SHALL be RAM-only, cleared by reboot,
`ClearSession`, and session teardown. *Verify:* I3–I5.

**R-2.3** Loading a provider SHALL require an on-device confirm that cannot be
suppressed. *Verify:* V14; `signed_metadata_confirm_load`.

**R-2.4** The device SHALL never represent a provider as KeepKey-endorsed.
It renders the provider's own alias and fingerprint plus "NOT verified by
KeepKey".

**Known deviation.** Disabling AdvancedMode makes a loaded signer **inert but
not erased**; re-enabling it in the same session restores it. The tier document
claims it is cleared. Recorded in atlas I6 as measured behaviour. **Decide in
7.16:** erase on disable, or correct the document.

### 3.3 Disclosure completeness

**R-3.1** Every byte covered by the signature SHALL be reachable on screen.
**R-3.2** A memo length that does not describe its own content SHALL be refused
(any NUL inside the declared length). *Verify:* Thorchain/Mayachain suites.
**R-3.3** An affiliate fee SHALL be displayed even when its affiliate slot is
empty. *Verify:* `MemoSwapFeeWithEmptyAffiliateIsStillShown` — 4 screens vs 3
without the fee.
**R-3.4** An amount SHALL never render as zero when non-zero, and never at the
wrong scale. *Verify:* `Solana.FormatTokenAmountNeverShowsZeroForNonzero`.
**R-3.5** A refused screen SHALL abort signing, never be re-asked differently.
*Verify:* `ThorchainMemoResult` CANCELLED vs UNPARSED.

### 3.4 Solana per-transaction context — NOT YET IMPLEMENTED

**R-4.1** The device SHOULD display provider-attested, transaction-bound context
for instructions whose accounts are not in the signed message (Address Lookup
Tables), behind AdvancedMode, additive.

**Status: not implemented.** `SolanaSignTx` reserves tags 5–8 for the
transaction-bound `KKSOLSW1` descriptor; only the reservation comment exists.
Today `solana.c:848` skips such instructions and renders **nothing**, so any
display is strictly additive.

Binding requirements when built (model: `signed_metadata_matches_tx`):
- bind to the exact message hash AND the resolved account list;
- reset the decode proof per call so a stale match cannot carry over;
- fail closed to the existing unverified review;
- render the provider alias and "NOT verified by KeepKey" like every other
  runtime-signer screen.

**This is the one genuine firmware build item in 7.15.**

### 3.5 Products

**R-5.1** Bitcoin-only SHALL compile out non-Bitcoin chains and Zcash privacy.
**R-5.2** The device SHALL report its product honestly in `firmware_variant`
(`KeepKeyBTC`/`EmulatorBTC`). *Verify:* atlas L; D-07.
**R-5.3** Non-Bitcoin paths SHALL refuse cleanly on bitcoin-only, not
half-render. *Verify:* atlas L.

### 3.6 Storage

**R-6.1** A signed UPGRADE SHALL never wipe. A DOWNGRADE wiping is expected.
**R-6.2** The committed record SHALL be recognisable on the next boot.
*Verify:* atlas U; D-02.
**R-6.3** Active flash format is V17. *Verify:* `test_active_flash_format_is_v17`.

### 3.7 Non-functional

**R-7.1** SRAM reserve ≥16,384 B, both products. *Currently:* full 18,172 B,
bitcoin-only 32,092 B.
**R-7.2** Both products build for ARM with `-Werror`.
**R-7.3** No CI job may silently skip. *Verify:* the aggregate `CI gate`.

---

## 4. Verification status

| | |
|---|---|
| `firmware-unit` (full) | 439/439 |
| `board-unit` | 12/12 |
| `firmware-unit` (bitcoin-only) | 63/63 |
| pyk suite (full emulator) | 620 passed, 33 skipped, 0 failed |
| pyk suite (bitcoin-only emulator) | 11/11 |
| ARM SRAM reserve | full 18,172 B · btc-only 32,092 B |
| Hardware (gate 3) | **NOT PERFORMED** |

---

## 5. Exit criteria

1. R-4.1 implemented, or explicitly deferred with the ALT gap documented as a
   known limitation.
2. Gate 3 OLED evidence per `7.15.0-rc21-clearsign-release-control.md`: a
   44-character base58 program ID, an 8-byte discriminator on its own screen,
   all four argument types, 16-character labels. **CI success alone does not
   prove this display boundary.**
3. The CI test report green with **nothing withheld**.
4. `solana-schemas-local.json` CI test key replaced or removed. **Host-side
   deliverable** — the file is not in this repository; it ships with the
   provider/Vault tooling. Listed here because a device cannot verify a
   schema signed with a test key, so it gates the release even though the
   fix lands elsewhere. **Host-side
   deliverable** — the file is not in this repository; it ships with the
   provider/Vault tooling. Listed here because a device cannot verify a
   schema signed with a test key, so it gates the release even though the
   fix lands elsewhere.
5. R-1.4 re-verified on the exact release candidate.
6. The D-01 sub-item (duplicate detector never observed firing correctly)
   resolved or accepted in writing.
