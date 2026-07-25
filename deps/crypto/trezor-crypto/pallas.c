/**
 * Copyright (c) 2025 KeepKey
 *
 * Pallas elliptic curve used by Zcash Orchard protocol.
 * Curve equation: y^2 = x^3 + 5 over Fp
 * p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
 * Generator G = (-1 mod p, 2)
 *
 * IMPORTANT: The trezor-crypto bignum library assumes primes in the range
 * [2^256 - 2^224, 2^256]. The Pallas prime (~2^254) falls outside this range,
 * so bn_multiply/bn_inverse/bn_fast_mod produce incorrect results.
 * pallas_ct.c implements fixed-width Montgomery field arithmetic and the
 * fixed-schedule projective path used for secret scalar multiplication.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include "pallas.h"

#include <string.h>

#include "blake2b.h"
#include "memzero.h"
#include "pallas_ct.h"

#define BN_BITS_PER_LIMB 29

/* ====================================================================
 * Constants
 * ==================================================================== */

const bignum256 pallas_prime = {
    /*.val =*/{0x00000001, 0x09698768, 0x133e46e6, 0x0d31f812, 0x00000224,
               0x00000000, 0x00000000, 0x00000000, 0x00400000}};

const bignum256 pallas_order = {
    /*.val =*/{0x00000001, 0x02375908, 0x052a3763, 0x0d31f813, 0x00000224,
               0x00000000, 0x00000000, 0x00000000, 0x00400000}};

const curve_point pallas_G = {
    /*.x =*/{/*.val =*/{0x00000000, 0x09698768, 0x133e46e6, 0x0d31f812,
                        0x00000224, 0x00000000, 0x00000000, 0x00000000,
                        0x00400000}},
    /*.y =*/{/*.val =*/{0x00000002, 0x00000000, 0x00000000, 0x00000000,
                        0x00000000, 0x00000000, 0x00000000, 0x00000000,
                        0x00000000}}};

/*
 * Full ecdsa_curve struct (kept for compatibility, but point_multiply
 * from ecdsa.c should NOT be used with Pallas - use pallas_scalar_mult_G).
 */
const ecdsa_curve pallas = {
    /* prime */
    {/*.val =*/{0x00000001, 0x09698768, 0x133e46e6, 0x0d31f812, 0x00000224,
                0x00000000, 0x00000000, 0x00000000, 0x00400000}},
    /* G */
    {/*.x =*/{/*.val =*/{0x00000000, 0x09698768, 0x133e46e6, 0x0d31f812,
                         0x00000224, 0x00000000, 0x00000000, 0x00000000,
                         0x00400000}},
     /*.y =*/{/*.val =*/{0x00000002, 0x00000000, 0x00000000, 0x00000000,
                         0x00000000, 0x00000000, 0x00000000, 0x00000000,
                         0x00000000}}},
    /* order */
    {/*.val =*/{0x00000001, 0x02375908, 0x052a3763, 0x0d31f813, 0x00000224,
                0x00000000, 0x00000000, 0x00000000, 0x00400000}},
    /* order_half */
    {/*.val =*/{0x00000000, 0x111bac84, 0x12951bb1, 0x0698fc09, 0x00000112,
                0x00000000, 0x00000000, 0x00000000, 0x00200000}},
    /* a */ 0,
    /* b = 5 */
    {/*.val =*/{5}}
#if USE_PRECOMPUTED_CP
    ,
    {{{{0}}}}
#endif
};

/* ====================================================================
 * Pallas Field Arithmetic
 * ==================================================================== */

/*
 * Field multiplication: x = k * x mod pallas_prime
 */
void pallas_mul_mod_p(bignum256* x, const bignum256* k) {
  pallas_ct_mul_mod_p(x, k);
}

/*
 * Scalar multiplication: x = k * x mod pallas_order
 */
void pallas_mul_mod_q(bignum256* x, const bignum256* k) {
  pallas_ct_mul_mod_q(x, k);
}

/*
 * Field addition: x = (a + b) mod pallas_prime
 */
void pallas_add_mod_p(const bignum256* a, const bignum256* b, bignum256* res) {
  pallas_ct_add_mod_p(a, b, res);
}

/*
 * Field subtraction: res = (a - b) mod pallas_prime
 */
void pallas_sub_mod_p(const bignum256* a, const bignum256* b, bignum256* res) {
  pallas_ct_sub_mod_p(a, b, res);
}

/*
 * Field inversion: x = x^(-1) mod pallas_prime
 * Uses Fermat's little theorem: x^(-1) = x^(p-2) mod p
 */
void pallas_inv_mod_p(bignum256* x) { pallas_ct_inv_mod_p(x); }

/*
 * Simple modular reduction: x = x mod pallas_prime
 * The input is a canonical 256-bit value represented as a bignum256.
 */
void pallas_mod_p(bignum256* x) { pallas_ct_mod_p(x); }

/*
 * Simple modular reduction: x = x mod pallas_order
 * The input is a canonical 256-bit value represented as a bignum256.
 */
void pallas_mod_q(bignum256* x) { pallas_ct_mod_q(x); }

/*
 * Scalar addition: a = (a + b) mod pallas_order
 */
void pallas_add_mod_q(bignum256* a, const bignum256* b) {
  pallas_ct_add_mod_q(a, b);
}

/*
 * Modular exponentiation: result = base^exp mod pallas_prime
 * Uses square-and-multiply (LSB to MSB).
 */
static void pallas_pow_mod_p(const bignum256* base, const bignum256* exp,
                             bignum256* result) {
  bn_zero(result);
  result->val[0] = 1;

  bignum256 b;
  bn_copy(base, &b);

  for (int bit = 0; bit < 255; bit++) {
    int limb_idx = bit / BN_BITS_PER_LIMB;
    int bit_idx = bit % BN_BITS_PER_LIMB;

    if ((exp->val[limb_idx] >> bit_idx) & 1) {
      pallas_mul_mod_p(result, &b);
    }
    bignum256 tmp;
    bn_copy(&b, &tmp);
    pallas_mul_mod_p(&b, &tmp);
  }
}

/*
 * Modular square root: n = sqrt(n) mod pallas_prime
 * Uses Tonelli-Shanks algorithm (required because p ≡ 1 mod 4).
 *
 * For Pallas: p - 1 = Q * 2^32 where Q is odd, S = 32.
 *
 * Returns 0 on success (n modified to sqrt), -1 if n is not a QR.
 */
int pallas_sqrt_mod_p(bignum256* n) {
  if (bn_is_zero(n)) return 0;

  /* p - 1 */
  bignum256 pm1;
  bn_copy(&pallas_prime, &pm1);
  pm1.val[0]--;

  /* Compute Q = (p-1) >> 32 (where S = 32, p-1 = Q * 2^S, Q odd) */
  /* 32 = 29 + 3, so shift right by 1 limb then 3 bits */
  bignum256 Q;
  int i;
  for (i = 0; i < 8; i++) Q.val[i] = pm1.val[i + 1];
  Q.val[8] = 0;
  for (i = 0; i < 8; i++) {
    Q.val[i] = (Q.val[i] >> 3) | ((Q.val[i + 1] & 0x7) << 26);
  }
  Q.val[8] >>= 3;

  /* (p-1)/2 for Euler criterion (QNR test) */
  bignum256 half_pm1;
  bn_copy(&pm1, &half_pm1);
  for (i = 0; i < 8; i++) {
    half_pm1.val[i] =
        (half_pm1.val[i] >> 1) | ((half_pm1.val[i + 1] & 0x1) << 28);
  }
  half_pm1.val[8] >>= 1;

  /* Find a quadratic non-residue z: z^((p-1)/2) ≡ -1 (mod p) */
  bignum256 z, test;
  for (uint32_t zi = 2; zi < 100; zi++) {
    bn_zero(&z);
    z.val[0] = zi;
    pallas_pow_mod_p(&z, &half_pm1, &test);
    bn_normalize(&test);
    if (bn_is_equal(&test, &pm1)) break;
  }

  /* Tonelli-Shanks initialization */
  int M = 32;
  bignum256 c;
  pallas_pow_mod_p(&z, &Q, &c); /* c = z^Q mod p */

  bignum256 t;
  pallas_pow_mod_p(n, &Q, &t); /* t = n^Q mod p */

  /* (Q+1)/2 */
  bignum256 Q_half;
  bn_copy(&Q, &Q_half);
  Q_half.val[0]++; /* Q is odd, so Q+1 is even */
  for (i = 0; i < 8; i++) {
    Q_half.val[i] = (Q_half.val[i] >> 1) | ((Q_half.val[i + 1] & 0x1) << 28);
  }
  Q_half.val[8] >>= 1;

  bignum256 R;
  pallas_pow_mod_p(n, &Q_half, &R); /* R = n^((Q+1)/2) mod p */

  bignum256 one;
  bn_zero(&one);
  one.val[0] = 1;

  /* Main loop */
  for (;;) {
    bn_normalize(&t);
    if (bn_is_zero(&t)) {
      bn_zero(n);
      return 0;
    }
    if (bn_is_equal(&t, &one)) {
      bn_copy(&R, n);
      return 0;
    }

    /* Find least i (1 ≤ i < M) such that t^(2^i) ≡ 1 (mod p) */
    bignum256 tmp;
    bn_copy(&t, &tmp);
    int ii;
    for (ii = 1; ii < M; ii++) {
      bignum256 sq;
      bn_copy(&tmp, &sq);
      pallas_mul_mod_p(&tmp, &sq); /* tmp = tmp^2 */
      bn_normalize(&tmp);
      if (bn_is_equal(&tmp, &one)) break;
    }

    if (ii >= M) {
      return -1; /* n is not a quadratic residue */
    }

    /* b = c^(2^(M-ii-1)) */
    bignum256 b;
    bn_copy(&c, &b);
    for (int j = 0; j < M - ii - 1; j++) {
      bignum256 sq;
      bn_copy(&b, &sq);
      pallas_mul_mod_p(&b, &sq); /* b = b^2 */
    }

    /* Update M, c, t, R */
    M = ii;

    /* c = b^2 */
    bn_copy(&b, &c);
    {
      bignum256 sq;
      bn_copy(&c, &sq);
      pallas_mul_mod_p(&c, &sq); /* c = c^2 = b^2 */
    }

    /* t = t * c (where c = b^2) */
    pallas_mul_mod_p(&t, &c); /* t = c * t = b^2 * t */

    /* R = R * b */
    pallas_mul_mod_p(&R, &b); /* R = b * R */
  }
}

/* ====================================================================
 * Pallas Point Operations (affine coordinates)
 * ==================================================================== */

static int pallas_point_is_infinity(const curve_point* p) {
  return bn_is_zero(&p->x) && bn_is_zero(&p->y);
}

/* Point addition uses the constant-time projective implementation. */
void pallas_point_add(const curve_point* p, const curve_point* q,
                      curve_point* res) {
  pallas_ct_point_add(p, q, res);
}

/* ====================================================================
 * Public API
 * ==================================================================== */

void pallas_scalar_mult_G(const bignum256* k, curve_point* res) {
  pallas_ct_point_mult(k, &pallas_G, res);
}

void pallas_point_mult(const bignum256* k, const curve_point* p,
                       curve_point* res) {
  pallas_ct_point_mult(k, p, res);
}

int pallas_point_is_identity(const curve_point* p) {
  if (!p) return 1;
  return pallas_point_is_infinity(p);
}

void pallas_point_encode(const curve_point* p, uint8_t out[32]) {
  if (!p || !out) return;

  memset(out, 0, 32);
  if (pallas_point_is_infinity(p)) return;

  bignum256 x;
  bn_copy(&p->x, &x);
  bn_write_le(&x, out);
  if (bn_is_odd(&p->y)) {
    out[31] |= 0x80;
  }
  memzero(&x, sizeof(x));
}

int pallas_expand_message_xmd_blake2b(const uint8_t* msg, size_t msg_len,
                                      const uint8_t* dst, size_t dst_len,
                                      uint8_t* out, size_t out_len) {
  enum {
    B_IN_BYTES = 64,
    R_IN_BYTES = 128,
  };

  if (!out || out_len == 0 || out_len > 0xffff) return -1;
  if ((!msg && msg_len != 0) || (!dst && dst_len != 0)) return -1;
  if (dst_len > 255) return -1;

  size_t ell = (out_len + B_IN_BYTES - 1) / B_IN_BYTES;
  if (ell == 0 || ell > 255) return -1;

  uint8_t dst_prime[256];
  uint8_t z_pad[R_IN_BYTES] = {0};
  uint8_t b0[B_IN_BYTES];
  uint8_t bi[B_IN_BYTES];
  uint8_t tmp[B_IN_BYTES];
  uint8_t len_bytes[2] = {(uint8_t)(out_len >> 8), (uint8_t)out_len};
  uint8_t zero = 0;
  uint8_t personal[16] = {0};
  BLAKE2B_CTX ctx;

  if (dst_len != 0) {
    memcpy(dst_prime, dst, dst_len);
  }
  dst_prime[dst_len] = (uint8_t)dst_len;
  size_t dst_prime_len = dst_len + 1;

  if (blake2b_InitPersonal(&ctx, B_IN_BYTES, personal, sizeof(personal)) != 0) {
    return -1;
  }
  blake2b_Update(&ctx, z_pad, sizeof(z_pad));
  blake2b_Update(&ctx, msg, msg_len);
  blake2b_Update(&ctx, len_bytes, sizeof(len_bytes));
  blake2b_Update(&ctx, &zero, 1);
  blake2b_Update(&ctx, dst_prime, dst_prime_len);
  if (blake2b_Final(&ctx, b0, sizeof(b0)) != 0) {
    memzero(&ctx, sizeof(ctx));
    return -1;
  }

  uint8_t ctr = 1;
  if (blake2b_InitPersonal(&ctx, B_IN_BYTES, personal, sizeof(personal)) != 0) {
    memzero(&ctx, sizeof(ctx));
    return -1;
  }
  blake2b_Update(&ctx, b0, sizeof(b0));
  blake2b_Update(&ctx, &ctr, 1);
  blake2b_Update(&ctx, dst_prime, dst_prime_len);
  if (blake2b_Final(&ctx, bi, sizeof(bi)) != 0) {
    memzero(&ctx, sizeof(ctx));
    return -1;
  }

  size_t take = out_len < B_IN_BYTES ? out_len : B_IN_BYTES;
  memcpy(out, bi, take);
  size_t produced = take;

  for (size_t i = 2; i <= ell; i++) {
    for (size_t j = 0; j < B_IN_BYTES; j++) {
      tmp[j] = b0[j] ^ bi[j];
    }

    ctr = (uint8_t)i;
    if (blake2b_InitPersonal(&ctx, B_IN_BYTES, personal, sizeof(personal)) !=
        0) {
      memzero(&ctx, sizeof(ctx));
      return -1;
    }
    blake2b_Update(&ctx, tmp, sizeof(tmp));
    blake2b_Update(&ctx, &ctr, 1);
    blake2b_Update(&ctx, dst_prime, dst_prime_len);
    if (blake2b_Final(&ctx, bi, sizeof(bi)) != 0) {
      memzero(&ctx, sizeof(ctx));
      return -1;
    }

    take = out_len - produced;
    if (take > B_IN_BYTES) take = B_IN_BYTES;
    memcpy(out + produced, bi, take);
    produced += take;
  }

  memzero(&ctx, sizeof(ctx));
  memzero(dst_prime, sizeof(dst_prime));
  memzero(b0, sizeof(b0));
  memzero(bi, sizeof(bi));
  memzero(tmp, sizeof(tmp));
  return 0;
}
