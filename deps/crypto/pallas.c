/*
 * Pallas curve field and scalar arithmetic for Zcash Orchard.
 *
 * Uses the bignum256 API from trezor-crypto for all modular
 * arithmetic.  This keeps the implementation small and leverages
 * the existing battle-tested bignum code.
 *
 * Copyright (C) 2025 KeepKey
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#include "pallas.h"
#include "memzero.h"

#include <string.h>

/*
 * Pallas scalar field order q (little-endian bytes):
 * q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
 */
static const uint8_t pallas_order_le[32] = {
    0x01, 0x00, 0x00, 0x00, 0x21, 0xeb, 0x46, 0x8c,
    0xdd, 0xa8, 0x94, 0x09, 0xfc, 0x98, 0x46, 0x22,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
};

/*
 * Pallas base field prime p (little-endian bytes):
 * p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
 */
static const uint8_t pallas_prime_le[32] = {
    0x01, 0x00, 0x00, 0x00, 0xed, 0x30, 0x2d, 0x99,
    0x1b, 0xf9, 0x4c, 0x09, 0xfc, 0x98, 0x46, 0x22,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
};

/* Globals — initialized lazily from LE byte arrays. */
bignum256 pallas_order;
bignum256 pallas_prime;
static int pallas_initialized = 0;

static void pallas_ensure_init(void) {
  if (pallas_initialized) return;
  bn_read_le(pallas_order_le, &pallas_order);
  bn_read_le(pallas_prime_le, &pallas_prime);
  pallas_initialized = 1;
}

void pallas_mod_q(bignum256 *a) {
  pallas_ensure_init();
  bn_mod(a, &pallas_order);
}

void pallas_mod_p(bignum256 *a) {
  pallas_ensure_init();
  bn_mod(a, &pallas_prime);
}

void pallas_mul_mod_q(bignum256 *a, const bignum256 *b) {
  pallas_ensure_init();
  bn_multiply(b, a, &pallas_order);
}

void pallas_mul_mod_p(bignum256 *a, const bignum256 *b) {
  pallas_ensure_init();
  bn_multiply(b, a, &pallas_prime);
}

void pallas_add_mod_q(bignum256 *a, const bignum256 *b) {
  pallas_ensure_init();
  bn_addmod(a, b, &pallas_order);
}

void pallas_add_mod_p(const bignum256 *a, const bignum256 *b, bignum256 *out) {
  pallas_ensure_init();
  bn_copy(a, out);
  bn_addmod(out, b, &pallas_prime);
}
