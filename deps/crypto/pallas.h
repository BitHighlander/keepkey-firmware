/*
 * Pallas curve field and scalar arithmetic for Zcash Orchard.
 *
 * The Pallas curve is one of the Pasta curves (Pallas/Vesta pair) used
 * in Zcash's Orchard shielded protocol.  It is a prime-order elliptic
 * curve y^2 = x^3 + 5 over Fp where:
 *
 *   p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
 *   q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
 *
 * p is the base field prime, q is the scalar field order.
 *
 * This implementation provides modular arithmetic operations needed by
 * ZIP-32 Orchard key derivation (ToScalar, ToBase) using the existing
 * bignum256 type from trezor-crypto.
 *
 * Copyright (C) 2025 KeepKey
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#ifndef PALLAS_H
#define PALLAS_H

#include "bignum.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Pallas scalar field order q (initialized lazily by first pallas_* call) */
extern bignum256 pallas_order;

/* Pallas base field prime p (initialized lazily by first pallas_* call) */
extern bignum256 pallas_prime;

/* Reduce a mod q (Pallas scalar field order) in-place. */
void pallas_mod_q(bignum256 *a);

/* Reduce a mod p (Pallas base field prime) in-place. */
void pallas_mod_p(bignum256 *a);

/* a = a * b mod q (Pallas scalar field). */
void pallas_mul_mod_q(bignum256 *a, const bignum256 *b);

/* a = a * b mod p (Pallas base field). */
void pallas_mul_mod_p(bignum256 *a, const bignum256 *b);

/* a = a + b mod q (Pallas scalar field), in-place. */
void pallas_add_mod_q(bignum256 *a, const bignum256 *b);

/* out = a + b mod p (Pallas base field). */
void pallas_add_mod_p(const bignum256 *a, const bignum256 *b, bignum256 *out);

#ifdef __cplusplus
}
#endif

#endif /* PALLAS_H */
