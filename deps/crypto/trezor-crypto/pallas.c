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
 * This file implements custom field arithmetic using Barrett reduction
 * to correctly handle the Pallas prime.
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

/* bn_multiply_long is defined in bignum.c (non-static) */
extern void bn_multiply_long(const bignum256 *k, const bignum256 *x,
                              uint32_t res[2 * 9]);

#define BN_LIMBS 9
#define BN_BITS_PER_LIMB 29
#define BN_LIMB_MASK ((1u << BN_BITS_PER_LIMB) - 1)

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
 * Barrett reduction constant for the Pallas prime:
 * mu_p = floor(2^510 / p)
 */
static const bignum256 mu_p = {
    /*.val =*/{0x1ffffffc, 0x1a59e25f, 0x1306e466, 0x0b381fb5, 0x1ffff76e,
               0x1fffffff, 0x1fffffff, 0x1fffffff, 0x00ffffff}};

/*
 * Barrett reduction constant for the Pallas order:
 * mu_q = floor(2^510 / q)
 */
static const bignum256 mu_q = {
    /*.val =*/{0x1ffffffc, 0x17229bdf, 0x0b572273, 0x0b381fb3, 0x1ffff76e,
               0x1fffffff, 0x1fffffff, 0x1fffffff, 0x00ffffff}};

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
 * Barrett Reduction for ~254-bit primes
 *
 * Given an 18-limb product (up to ~510 bits), reduce mod prime.
 * Uses Barrett: q_hat = floor(floor(x / 2^254) * mu / 2^256)
 *               r = x - q_hat * prime
 *               while r >= prime: r -= prime
 * ==================================================================== */

/*
 * Shift an 18-limb number right by 254 bits.
 * 254 = 8*29 + 22, so we skip 8 limbs and shift remaining by 22 bits.
 */
static void shift_right_254(const uint32_t in[18], bignum256 *out) {
  for (int i = 0; i < BN_LIMBS; i++) {
    uint32_t lo = in[i + 8] >> 22;
    uint32_t hi = (i + 9 < 18) ? (in[i + 9] << 7) : 0;
    out->val[i] = (lo | hi) & BN_LIMB_MASK;
  }
}

/*
 * Shift an 18-limb number right by 256 bits.
 * 256 = 8*29 + 24, so we skip 8 limbs and shift remaining by 24 bits.
 */
static void shift_right_256(const uint32_t in[18], bignum256 *out) {
  for (int i = 0; i < BN_LIMBS; i++) {
    uint32_t lo = in[i + 8] >> 24;
    uint32_t hi = (i + 9 < 18) ? (in[i + 9] << 5) : 0;
    out->val[i] = (lo | hi) & BN_LIMB_MASK;
  }
}

/*
 * Compare two bignum256 values (both must be normalized).
 * Returns 1 if a >= b, 0 otherwise.
 */
static int bn_gte(const bignum256 *a, const bignum256 *b) {
  for (int i = BN_LIMBS - 1; i >= 0; i--) {
    if (a->val[i] > b->val[i]) return 1;
    if (a->val[i] < b->val[i]) return 0;
  }
  return 1; /* equal */
}

/*
 * Subtract b from a, storing result in res. Assumes a >= b.
 * All operands must be normalized.
 */
static void bn_sub(const bignum256 *a, const bignum256 *b, bignum256 *res) {
  int32_t borrow = 0;
  for (int i = 0; i < BN_LIMBS; i++) {
    int32_t diff = (int32_t)a->val[i] - (int32_t)b->val[i] + borrow;
    if (diff < 0) {
      diff += (1 << BN_BITS_PER_LIMB);
      borrow = -1;
    } else {
      borrow = 0;
    }
    res->val[i] = (uint32_t)diff;
  }
}

/*
 * Barrett reduction: reduce an 18-limb product mod a ~254-bit prime.
 *
 * prime: the modulus (~254-255 bits)
 * mu: precomputed floor(2^510 / prime) (~256 bits)
 * res[18]: input product (up to ~510 bits)
 * out: output, reduced to [0, prime)
 */
static void pallas_barrett_reduce(const uint32_t res[18],
                                   const bignum256 *prime,
                                   const bignum256 *mu, bignum256 *out) {
  /* Step 1: q_hat = floor(floor(x / 2^254) * mu / 2^256) */
  bignum256 x_shifted;
  shift_right_254(res, &x_shifted);
  bn_normalize(&x_shifted);

  uint32_t qmu[18] = {0};
  bn_multiply_long(&x_shifted, mu, qmu);

  bignum256 q_hat;
  shift_right_256(qmu, &q_hat);
  bn_normalize(&q_hat);

  /* Step 2: r = x - q_hat * prime (low 9 limbs only) */
  uint32_t qp[18] = {0};
  bn_multiply_long(&q_hat, prime, qp);

  /* Compute r = x - q*p using 9 low limbs.
   * The true result fits in ~256 bits (< 3*prime). */
  int64_t borrow = 0;
  for (int i = 0; i < BN_LIMBS; i++) {
    int64_t diff = (int64_t)res[i] - (int64_t)qp[i] + borrow;
    out->val[i] = (uint32_t)(diff & BN_LIMB_MASK);
    borrow = diff >> BN_BITS_PER_LIMB;
  }
  bn_normalize(out);

  /* Step 3: while r >= prime, r -= prime (at most 3 times) */
  for (int i = 0; i < 3; i++) {
    if (bn_gte(out, prime)) {
      bn_sub(out, prime, out);
    }
  }
}

/* ====================================================================
 * Pallas Field Arithmetic
 * ==================================================================== */

/*
 * Field multiplication: x = k * x mod pallas_prime
 */
void pallas_mul_mod_p(bignum256 *x, const bignum256 *k) {
  uint32_t res[18] = {0};
  bn_multiply_long(k, x, res);
  pallas_barrett_reduce(res, &pallas_prime, &mu_p, x);
}

/*
 * Scalar multiplication: x = k * x mod pallas_order
 */
void pallas_mul_mod_q(bignum256 *x, const bignum256 *k) {
  uint32_t res[18] = {0};
  bn_multiply_long(k, x, res);
  pallas_barrett_reduce(res, &pallas_order, &mu_q, x);
}

/*
 * Field addition: x = (a + b) mod pallas_prime
 */
void pallas_add_mod_p(const bignum256 *a, const bignum256 *b,
                       bignum256 *res) {
  uint32_t carry = 0;
  for (int i = 0; i < BN_LIMBS; i++) {
    carry += a->val[i] + b->val[i];
    res->val[i] = carry & BN_LIMB_MASK;
    carry >>= BN_BITS_PER_LIMB;
  }
  bn_normalize(res);
  if (bn_gte(res, &pallas_prime)) {
    bn_sub(res, &pallas_prime, res);
  }
}

/*
 * Field subtraction: res = (a - b) mod pallas_prime
 */
void pallas_sub_mod_p(const bignum256 *a, const bignum256 *b,
                       bignum256 *res) {
  if (bn_gte(a, b)) {
    bn_sub(a, b, res);
  } else {
    /* a < b: res = a + prime - b = prime - (b - a) */
    bignum256 tmp;
    bn_sub(b, a, &tmp);
    bn_sub(&pallas_prime, &tmp, res);
  }
}

/*
 * Field inversion: x = x^(-1) mod pallas_prime
 * Uses Fermat's little theorem: x^(-1) = x^(p-2) mod p
 */
void pallas_inv_mod_p(bignum256 *x) {
  /* Compute e = p - 2 with proper borrow (since p.val[0] = 1 < 2) */
  bignum256 e;
  bn_copy(&pallas_prime, &e);
  /* val[0] = 1, so 1 - 2 requires borrow from val[1] */
  e.val[0] = e.val[0] + (1u << BN_BITS_PER_LIMB) - 2;  /* 1 + 2^29 - 2 = 0x1FFFFFFF */
  e.val[1] -= 1;  /* borrow */

  /* Square-and-multiply: result = x^e mod p */
  bignum256 result;
  bn_one(&result);

  bignum256 base;
  bn_copy(x, &base);

  /* Process each bit of e from LSB to MSB */
  for (int bit = 0; bit < 255; bit++) {
    int limb_idx = bit / BN_BITS_PER_LIMB;
    int bit_idx = bit % BN_BITS_PER_LIMB;

    if ((e.val[limb_idx] >> bit_idx) & 1) {
      pallas_mul_mod_p(&result, &base);
    }
    /* Square the base */
    bignum256 tmp;
    bn_copy(&base, &tmp);
    pallas_mul_mod_p(&base, &tmp);
  }

  bn_copy(&result, x);
  memzero(&result, sizeof(result));
  memzero(&base, sizeof(base));
}

/*
 * Simple modular reduction: x = x mod pallas_prime
 * For values already < 2^261 (bignum256 range).
 */
void pallas_mod_p(bignum256 *x) {
  bn_normalize(x);
  while (bn_gte(x, &pallas_prime)) {
    bn_sub(x, &pallas_prime, x);
  }
}

/*
 * Simple modular reduction: x = x mod pallas_order
 * For values already < 2^261 (bignum256 range).
 */
void pallas_mod_q(bignum256 *x) {
  bn_normalize(x);
  while (bn_gte(x, &pallas_order)) {
    bn_sub(x, &pallas_order, x);
  }
}

/*
 * Scalar addition: a = (a + b) mod pallas_order
 */
void pallas_add_mod_q(bignum256 *a, const bignum256 *b) {
  uint32_t carry = 0;
  for (int i = 0; i < BN_LIMBS; i++) {
    carry += a->val[i] + b->val[i];
    a->val[i] = carry & BN_LIMB_MASK;
    carry >>= BN_BITS_PER_LIMB;
  }
  pallas_mod_q(a);
}

/*
 * Modular exponentiation: result = base^exp mod pallas_prime
 * Uses square-and-multiply (LSB to MSB).
 */
static void pallas_pow_mod_p(const bignum256 *base, const bignum256 *exp,
                              bignum256 *result) {
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
int pallas_sqrt_mod_p(bignum256 *n) {
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
    half_pm1.val[i] = (half_pm1.val[i] >> 1) | ((half_pm1.val[i + 1] & 0x1) << 28);
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
  pallas_pow_mod_p(&z, &Q, &c);       /* c = z^Q mod p */

  bignum256 t;
  pallas_pow_mod_p(n, &Q, &t);        /* t = n^Q mod p */

  /* (Q+1)/2 */
  bignum256 Q_half;
  bn_copy(&Q, &Q_half);
  Q_half.val[0]++;  /* Q is odd, so Q+1 is even */
  for (i = 0; i < 8; i++) {
    Q_half.val[i] = (Q_half.val[i] >> 1) | ((Q_half.val[i + 1] & 0x1) << 28);
  }
  Q_half.val[8] >>= 1;

  bignum256 R;
  pallas_pow_mod_p(n, &Q_half, &R);   /* R = n^((Q+1)/2) mod p */

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
      pallas_mul_mod_p(&tmp, &sq);   /* tmp = tmp^2 */
      bn_normalize(&tmp);
      if (bn_is_equal(&tmp, &one)) break;
    }

    if (ii >= M) {
      return -1;  /* n is not a quadratic residue */
    }

    /* b = c^(2^(M-ii-1)) */
    bignum256 b;
    bn_copy(&c, &b);
    for (int j = 0; j < M - ii - 1; j++) {
      bignum256 sq;
      bn_copy(&b, &sq);
      pallas_mul_mod_p(&b, &sq);     /* b = b^2 */
    }

    /* Update M, c, t, R */
    M = ii;

    /* c = b^2 */
    bn_copy(&b, &c);
    {
      bignum256 sq;
      bn_copy(&c, &sq);
      pallas_mul_mod_p(&c, &sq);     /* c = c^2 = b^2 */
    }

    /* t = t * c (where c = b^2) */
    pallas_mul_mod_p(&t, &c);        /* t = c * t = b^2 * t */

    /* R = R * b */
    pallas_mul_mod_p(&R, &b);        /* R = b * R */
  }
}

/* ====================================================================
 * Pallas Point Operations (affine coordinates)
 * ==================================================================== */

static int pallas_point_is_infinity(const curve_point *p) {
  return bn_is_zero(&p->x) && bn_is_zero(&p->y);
}

static void pallas_point_set_infinity(curve_point *p) {
  bn_zero(&p->x);
  bn_zero(&p->y);
}

/*
 * Point doubling: res = 2*P on Pallas curve (y^2 = x^3 + 5, a=0)
 * Formula: lambda = 3*x^2 / (2*y)
 *          xr = lambda^2 - 2*x
 *          yr = lambda*(x - xr) - y
 */
static void pallas_point_dbl(const curve_point *p, curve_point *res) {
  if (pallas_point_is_infinity(p) || bn_is_zero(&p->y)) {
    pallas_point_set_infinity(res);
    return;
  }

  bignum256 lambda, xr, yr, tmp, tmp2;

  /* lambda = 3*x^2 / (2*y) mod p */
  /* Numerator: 3*x^2 */
  bn_copy(&p->x, &tmp);
  pallas_mul_mod_p(&tmp, &p->x); /* tmp = x^2 */
  bn_copy(&tmp, &tmp2);
  pallas_add_mod_p(&tmp, &tmp2, &lambda);    /* lambda = 2*x^2 */
  pallas_add_mod_p(&lambda, &tmp2, &lambda); /* lambda = 3*x^2 */

  /* Denominator: 2*y */
  pallas_add_mod_p(&p->y, &p->y, &tmp); /* tmp = 2*y */

  /* Invert denominator */
  pallas_inv_mod_p(&tmp); /* tmp = 1/(2*y) */

  /* lambda = 3*x^2 * (1/(2*y)) */
  pallas_mul_mod_p(&lambda, &tmp);

  /* xr = lambda^2 - 2*x */
  bn_copy(&lambda, &xr);
  pallas_mul_mod_p(&xr, &lambda); /* xr = lambda^2 */
  pallas_add_mod_p(&p->x, &p->x, &tmp); /* tmp = 2*x */
  pallas_sub_mod_p(&xr, &tmp, &xr); /* xr = lambda^2 - 2*x */

  /* yr = lambda*(x - xr) - y */
  pallas_sub_mod_p(&p->x, &xr, &yr); /* yr = x - xr */
  pallas_mul_mod_p(&yr, &lambda); /* yr = lambda*(x - xr) */
  pallas_sub_mod_p(&yr, &p->y, &yr); /* yr = lambda*(x-xr) - y */

  bn_copy(&xr, &res->x);
  bn_copy(&yr, &res->y);
}

/*
 * Point addition: res = P + Q on Pallas curve
 */
void pallas_point_add(const curve_point *p, const curve_point *q,
                       curve_point *res) {
  if (pallas_point_is_infinity(p)) {
    *res = *q;
    return;
  }
  if (pallas_point_is_infinity(q)) {
    *res = *p;
    return;
  }

  /* Check if P == Q (use doubling) */
  bignum256 px_norm, qx_norm, py_norm, qy_norm;
  bn_copy(&p->x, &px_norm);
  bn_copy(&q->x, &qx_norm);
  bn_copy(&p->y, &py_norm);
  bn_copy(&q->y, &qy_norm);
  bn_normalize(&px_norm);
  bn_normalize(&qx_norm);
  bn_normalize(&py_norm);
  bn_normalize(&qy_norm);

  int x_equal = 1, y_equal = 1;
  for (int i = 0; i < BN_LIMBS; i++) {
    if (px_norm.val[i] != qx_norm.val[i]) { x_equal = 0; break; }
  }
  if (x_equal) {
    for (int i = 0; i < BN_LIMBS; i++) {
      if (py_norm.val[i] != qy_norm.val[i]) { y_equal = 0; break; }
    }
    if (y_equal) {
      pallas_point_dbl(p, res);
      return;
    }
    /* P.x == Q.x but P.y != Q.y → P + Q = O (point at infinity) */
    pallas_point_set_infinity(res);
    return;
  }

  bignum256 lambda, xr, yr, tmp;

  /* lambda = (Q.y - P.y) / (Q.x - P.x) mod p */
  pallas_sub_mod_p(&q->y, &p->y, &lambda); /* num = Q.y - P.y */
  pallas_sub_mod_p(&q->x, &p->x, &tmp);     /* den = Q.x - P.x */
  pallas_inv_mod_p(&tmp);                     /* den = 1/(Q.x - P.x) */
  pallas_mul_mod_p(&lambda, &tmp);            /* lambda = num/den */

  /* xr = lambda^2 - P.x - Q.x */
  bn_copy(&lambda, &xr);
  pallas_mul_mod_p(&xr, &lambda);             /* xr = lambda^2 */
  pallas_sub_mod_p(&xr, &p->x, &xr);          /* xr -= P.x */
  pallas_sub_mod_p(&xr, &q->x, &xr);          /* xr -= Q.x */

  /* yr = lambda*(P.x - xr) - P.y */
  pallas_sub_mod_p(&p->x, &xr, &yr);          /* yr = P.x - xr */
  pallas_mul_mod_p(&yr, &lambda);              /* yr *= lambda */
  pallas_sub_mod_p(&yr, &p->y, &yr);           /* yr -= P.y */

  bn_copy(&xr, &res->x);
  bn_copy(&yr, &res->y);
}

/* ====================================================================
 * Scalar Multiplication (double-and-add, left-to-right)
 * ==================================================================== */

/*
 * Compute res = k * P on Pallas.
 * Uses the double-and-add algorithm.
 * k must be in [1, order-1].
 */
static void pallas_scalar_mult_impl(const bignum256 *k, const curve_point *p,
                                     curve_point *res) {
  /* Find the highest set bit */
  int highest_bit = -1;
  for (int i = BN_LIMBS - 1; i >= 0; i--) {
    if (k->val[i] != 0) {
      uint32_t v = k->val[i];
      int bit = BN_BITS_PER_LIMB - 1;
      while (bit >= 0 && !((v >> bit) & 1)) bit--;
      highest_bit = i * BN_BITS_PER_LIMB + bit;
      break;
    }
  }

  if (highest_bit < 0) {
    /* k == 0 */
    pallas_point_set_infinity(res);
    return;
  }

  /* Initialize res = P (for the highest bit) */
  *res = *p;

  /* Process remaining bits from second-highest down to 0 */
  for (int bit = highest_bit - 1; bit >= 0; bit--) {
    /* Double */
    curve_point tmp;
    pallas_point_dbl(res, &tmp);
    *res = tmp;

    /* Add if bit is set */
    int limb_idx = bit / BN_BITS_PER_LIMB;
    int bit_idx = bit % BN_BITS_PER_LIMB;
    if ((k->val[limb_idx] >> bit_idx) & 1) {
      pallas_point_add(res, p, &tmp);
      *res = tmp;
    }
  }
}

/* ====================================================================
 * Public API
 * ==================================================================== */

void pallas_scalar_mult_G(const bignum256 *k, curve_point *res) {
  if (bn_is_zero(k)) {
    pallas_point_set_infinity(res);
    return;
  }
  pallas_scalar_mult_impl(k, &pallas_G, res);
}

void pallas_point_mult(const bignum256 *k, const curve_point *p,
                        curve_point *res) {
  if (bn_is_zero(k)) {
    pallas_point_set_infinity(res);
    return;
  }
  pallas_scalar_mult_impl(k, p, res);
}

int pallas_point_is_identity(const curve_point *p) {
  if (!p) return 1;
  return pallas_point_is_infinity(p);
}

void pallas_point_encode(const curve_point *p, uint8_t out[32]) {
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

int pallas_expand_message_xmd_blake2b(const uint8_t *msg, size_t msg_len,
                                      const uint8_t *dst, size_t dst_len,
                                      uint8_t *out, size_t out_len) {
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
    if (blake2b_InitPersonal(&ctx, B_IN_BYTES, personal, sizeof(personal)) != 0) {
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
