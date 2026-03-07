# Vendored Crypto Library — Provenance

## Source

- **Repository**: https://github.com/markrypt0/hw-crypto
- **Commit**: `34dbef959435dcab8b13e3d4776294cc762e12e5`
- **Date**: 2025-03-14
- **Description**: "initial commit from keepkey branch of trezor crypto"

This library originates from the [trezor-firmware](https://github.com/trezor/trezor-firmware) crypto module, forked through KeepKey's maintained branch. The `markrypt0/hw-crypto` fork adds **Blake2b personalization** (`blake2b_InitPersonal`) required for Zcash and Solana support.

## What was vendored

103 source files from `crypto/` subdirectory (C source, headers, precomputed tables).

## What was intentionally stripped

The following directories/files from hw-crypto were **not vendored** (not needed for firmware compilation):

- `crypto/tests/` — test harness (test_check.c, test_openssl.c, etc.)
- `crypto/tools/` — standalone utilities (mktable.c, xpubaddrgen.c, etc.)
- `crypto/fuzzer/` — fuzz testing harness
- `crypto/gui/` — Qt GUI tools
- `crypto/monero/` — Monero-specific crypto (USE_MONERO=0)
- `crypto/chacha20poly1305/` — ChaCha20-Poly1305 AEAD (not needed, breaks ARM xmmintrin.h)
- `crypto/setup.py` — Python bindings
- `crypto/.git*` — git metadata
- `crypto/Makefile`, `crypto/AUTHORS`, `crypto/CONTRIBUTORS`, `crypto/LICENSE`, `crypto/README.md`

Additionally, the following files were vendored in the initial commit but later removed as dead code (not compiled by CMakeLists.txt):

- `schnorr.c`, `schnorr.h` — Schnorr signatures (not used by firmware)
- `chacha_drbg.c`, `chacha_drbg.h` — ChaCha DRBG (depends on missing chacha20poly1305/)
- `slip39.c`, `slip39.h`, `slip39_wordlist.h` — SLIP-0039 Shamir backup (not used)
- `shamir.c`, `shamir.h` — Shamir secret sharing (not used)

## Key modifications from upstream trezor-crypto

The hw-crypto fork adds these changes over the base trezor-crypto:

1. **`blake2b.c` / `blake2b.h`**: Added `blake2b_InitPersonal()` function for Blake2b with personalization parameter
2. **`hasher.c` / `hasher.h`**: Added `HASHER_BLAKE2B_PERSONAL` enum and `hasher_InitParam()` to thread personalization through the generic hasher API

## Compile-time configuration

The firmware's root `CMakeLists.txt` overrides `options.h` defaults:

| Define | options.h default | Firmware override |
|--------|-------------------|-------------------|
| `USE_ETHEREUM` | 0 | **1** |
| `USE_KECCAK` | 0 | **1** |
| `USE_GRAPHENE` | 1 | **0** |
| `USE_CARDANO` | 0 | 0 |
| `USE_MONERO` | 0 | 0 |
| `USE_NEM` | 0 | 0 |
| `USE_NANO` | (not in options.h) | **1** |
| `RAND_PLATFORM_INDEPENDENT` | (not defined) | **0** (forces HW RNG) |
| `USE_PRECOMPUTED_CP` | 1 | **0** |

## Verification

Run `scripts/verify-crypto-vendor.sh` to diff vendored files against the upstream hw-crypto commit.
