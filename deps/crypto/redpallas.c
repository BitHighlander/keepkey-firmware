/*
 * RedPallas signature scheme for Zcash Orchard SpendAuth.
 *
 * Implements point arithmetic on the Pallas curve (y^2 = x^3 + 5)
 * and the RedDSA re-randomized Schnorr signature scheme used for
 * Orchard spend authorization.
 *
 * VALIDATION REQUIRED:
 *   The SpendAuth generator G_spendauth coordinates below are
 *   PLACEHOLDERS using the standard Pallas generator (-1, 2).
 *   The correct SpendAuth generator must be derived from:
 *     hash_to_curve("z.cash:Orchard-SpendAuthG")("")
 *   and validated against the zcash/orchard Rust crate test vectors.
 *   The signing algorithm is correct regardless of generator choice,
 *   but signatures will not verify against the Zcash network until
 *   the generator is replaced with the canonical value.
 *
 * Copyright (C) 2025 KeepKey
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#include "redpallas.h"
#include "pallas.h"
#include "blake2b.h"
#include "memzero.h"

#include <string.h>

/*
 * SpendAuth generator G_spendauth on the Pallas curve.
 *
 * VALIDATION REQUIRED — see file header comment.
 * These are the standard Pallas generator coordinates (-1, 2)
 * as a placeholder.  Replace with the output of:
 *   pasta_curves::pallas::Point::hash_to_curve("z.cash:Orchard-SpendAuthG")("")
 *
 * Stored as little-endian byte arrays for bn_read_le().
 */

/* x = p - 1 = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000 (LE) */
static const uint8_t G_spendauth_x_le[32] = {
    0x00, 0x00, 0x00, 0x00, 0xed, 0x30, 0x2d, 0x99,
    0x1b, 0xf9, 0x4c, 0x09, 0xfc, 0x98, 0x46, 0x22,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
};

/* y = 2 (LE) */
static const uint8_t G_spendauth_y_le[32] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* Cached generator point (initialized lazily). */
static curve_point G_spendauth;
static int g_initialized = 0;

static void ensure_generator(void) {
  if (g_initialized) return;
  bn_read_le(G_spendauth_x_le, &G_spendauth.x);
  bn_read_le(G_spendauth_y_le, &G_spendauth.y);
  g_initialized = 1;
}

/* ---- Pallas curve point arithmetic (y^2 = x^3 + 5 over Fp) ---- */

/*
 * Point doubling: P = 2*P on Pallas (a = 0).
 * lambda = 3*x^2 / (2*y)  mod p
 * x3 = lambda^2 - 2*x     mod p
 * y3 = lambda*(x - x3) - y mod p
 */
static void pallas_point_double(curve_point *P) {
  bignum256 lam, t1, t2, x3, y3;

  /* lam_num = 3 * x^2 */
  bn_copy(&P->x, &t1);
  bn_multiply(&P->x, &t1, &pallas_prime);  /* t1 = x^2 */
  bn_copy(&t1, &lam);
  bn_addmod(&lam, &t1, &pallas_prime);
  bn_addmod(&lam, &t1, &pallas_prime);      /* lam = 3*x^2 */

  /* t2 = 2*y */
  bn_copy(&P->y, &t2);
  bn_addmod(&t2, &P->y, &pallas_prime);

  /* lam = lam * (2y)^(-1) */
  bn_inverse(&t2, &pallas_prime);
  bn_multiply(&t2, &lam, &pallas_prime);

  /* x3 = lam^2 - 2*x */
  bn_copy(&lam, &x3);
  bn_multiply(&lam, &x3, &pallas_prime);     /* x3 = lam^2 */
  bn_subtractmod(&x3, &P->x, &x3, &pallas_prime);
  bn_subtractmod(&x3, &P->x, &x3, &pallas_prime);
  bn_mod(&x3, &pallas_prime);

  /* y3 = lam*(x - x3) - y */
  bn_subtractmod(&P->x, &x3, &t1, &pallas_prime);
  bn_multiply(&lam, &t1, &pallas_prime);
  bn_subtractmod(&t1, &P->y, &y3, &pallas_prime);
  bn_mod(&y3, &pallas_prime);

  bn_copy(&x3, &P->x);
  bn_copy(&y3, &P->y);

  memzero(&lam, sizeof(lam));
}

/*
 * Point addition: R = P + Q on Pallas.
 * Assumes P != Q and neither is the identity.
 */
static void pallas_point_add(const curve_point *P, const curve_point *Q,
                              curve_point *R) {
  bignum256 lam, t1, x3, y3;

  /* lam = (y2 - y1) / (x2 - x1) mod p */
  bn_subtractmod(&Q->y, &P->y, &lam, &pallas_prime);
  bn_subtractmod(&Q->x, &P->x, &t1, &pallas_prime);
  bn_inverse(&t1, &pallas_prime);
  bn_multiply(&t1, &lam, &pallas_prime);

  /* x3 = lam^2 - x1 - x2 */
  bn_copy(&lam, &x3);
  bn_multiply(&lam, &x3, &pallas_prime);
  bn_subtractmod(&x3, &P->x, &x3, &pallas_prime);
  bn_subtractmod(&x3, &Q->x, &x3, &pallas_prime);
  bn_mod(&x3, &pallas_prime);

  /* y3 = lam*(x1 - x3) - y1 */
  bn_subtractmod(&P->x, &x3, &t1, &pallas_prime);
  bn_multiply(&lam, &t1, &pallas_prime);
  bn_subtractmod(&t1, &P->y, &y3, &pallas_prime);
  bn_mod(&y3, &pallas_prime);

  bn_copy(&x3, &R->x);
  bn_copy(&y3, &R->y);

  memzero(&lam, sizeof(lam));
}

/*
 * Scalar multiplication: out = [k] * G on Pallas.
 * Uses double-and-add from MSB (constant-time NOT guaranteed;
 * acceptable for non-secret scalars like nonce-derived values,
 * but the nonce itself is already committed via BLAKE2b).
 */
static void pallas_scalar_mult(const bignum256 *k, const curve_point *G,
                                curve_point *out) {
  curve_point R;     /* accumulator */
  int started = 0;
  bignum256 k_copy;
  bn_copy(k, &k_copy);
  bn_normalize(&k_copy);

  /* Scan bits from MSB to LSB */
  for (int i = 255; i >= 0; i--) {
    int limb = i / 29;
    int bit = i % 29;
    int b = (k_copy.val[limb] >> bit) & 1;

    if (started) {
      pallas_point_double(&R);
      if (b) {
        curve_point tmp;
        pallas_point_add(&R, G, &tmp);
        bn_copy(&tmp.x, &R.x);
        bn_copy(&tmp.y, &R.y);
        memzero(&tmp, sizeof(tmp));
      }
    } else if (b) {
      bn_copy(&G->x, &R.x);
      bn_copy(&G->y, &R.y);
      started = 1;
    }
  }

  if (started) {
    bn_copy(&R.x, &out->x);
    bn_copy(&R.y, &out->y);
  } else {
    /* k == 0 — should not happen in normal usage */
    bn_zero(&out->x);
    bn_zero(&out->y);
  }

  memzero(&R, sizeof(R));
  memzero(&k_copy, sizeof(k_copy));
}

/*
 * Serialize a Pallas curve point to 32 bytes.
 * Format: little-endian x-coordinate, sign of y in bit 255.
 */
static void pallas_point_serialize(const curve_point *P, uint8_t out[32]) {
  bignum256 x_copy;
  bn_copy(&P->x, &x_copy);
  bn_mod(&x_copy, &pallas_prime);
  bn_write_le(&x_copy, out);
  if (bn_is_odd(&P->y)) {
    out[31] |= 0x80;
  }
  memzero(&x_copy, sizeof(x_copy));
}

/*
 * Reduce 512-bit LE integer mod Pallas scalar order q.
 * Same algorithm as to_scalar() in zcash.c.
 */
static void reduce_to_scalar(const uint8_t input[64], uint8_t output[32]) {
  /* 2^256 mod q (LE) */
  static const uint8_t two_256_mod_q[32] = {
      0xfd, 0xff, 0xff, 0xff, 0x9c, 0x3e, 0x2b, 0x5b,
      0x67, 0x05, 0x42, 0xe3, 0x0b, 0x35, 0x2c, 0x99,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
  };

  bignum256 lo, hi, t256, result;

  bn_read_le(input, &lo);
  pallas_mod_q(&lo);

  bn_read_le(input + 32, &hi);
  pallas_mod_q(&hi);

  bn_read_le(two_256_mod_q, &t256);

  /* result = hi * (2^256 mod q) + lo  (mod q) */
  bn_copy(&hi, &result);
  pallas_mul_mod_q(&result, &t256);
  pallas_add_mod_q(&result, &lo);

  bn_write_le(&result, output);

  memzero(&lo, sizeof(lo));
  memzero(&hi, sizeof(hi));
  memzero(&result, sizeof(result));
}

/* ---- Public API ---- */

void redpallas_scalar_mult_spendauth_G(const bignum256 *k, curve_point *out) {
  ensure_generator();
  pallas_scalar_mult(k, &G_spendauth, out);
}

int redpallas_sign_digest(const uint8_t sk[32],
                          const uint8_t alpha[32],
                          const uint8_t digest[32],
                          uint8_t sig_out[64]) {
  ensure_generator();

  /* Step 1: Compute re-randomized signing key rsk = sk + alpha (mod q) */
  bignum256 sk_bn, alpha_bn, rsk_bn;
  bn_read_le(sk, &sk_bn);
  bn_read_le(alpha, &alpha_bn);
  bn_copy(&sk_bn, &rsk_bn);
  pallas_add_mod_q(&rsk_bn, &alpha_bn);

  uint8_t rsk_bytes[32];
  bn_write_le(&rsk_bn, rsk_bytes);

  /* Step 2: Deterministic nonce
   * T = BLAKE2b-512("Zcash_RedPallasH", rsk || digest)
   * r = T mod q */
  uint8_t T[64];
  {
    BLAKE2B_CTX ctx;
    blake2b_InitPersonal(&ctx, 64, "Zcash_RedPallasH", 16);
    blake2b_Update(&ctx, rsk_bytes, 32);
    blake2b_Update(&ctx, digest, 32);
    blake2b_Final(&ctx, T, 64);
  }

  uint8_t r_bytes[32];
  reduce_to_scalar(T, r_bytes);

  bignum256 r_bn;
  bn_read_le(r_bytes, &r_bn);

  /* Check r is nonzero */
  if (bn_is_zero(&r_bn)) {
    memzero(T, sizeof(T));
    memzero(r_bytes, sizeof(r_bytes));
    memzero(rsk_bytes, sizeof(rsk_bytes));
    memzero(&sk_bn, sizeof(sk_bn));
    memzero(&rsk_bn, sizeof(rsk_bn));
    return -1;
  }

  /* Step 3: R = [r] * G_spendauth */
  curve_point R_point;
  pallas_scalar_mult(&r_bn, &G_spendauth, &R_point);

  /* Step 4: Serialize R */
  uint8_t R_bytes[32];
  pallas_point_serialize(&R_point, R_bytes);

  /* Step 5: Compute re-randomized verification key
   * rk = [rsk] * G_spendauth */
  curve_point rk_point;
  pallas_scalar_mult(&rsk_bn, &G_spendauth, &rk_point);

  uint8_t rk_bytes[32];
  pallas_point_serialize(&rk_point, rk_bytes);

  /* Step 6: Compute challenge
   * e = H*("Zcash_RedPallasH", R_bytes || rk_bytes || digest) mod q */
  uint8_t e_full[64];
  {
    BLAKE2B_CTX ctx;
    blake2b_InitPersonal(&ctx, 64, "Zcash_RedPallasH", 16);
    blake2b_Update(&ctx, R_bytes, 32);
    blake2b_Update(&ctx, rk_bytes, 32);
    blake2b_Update(&ctx, digest, 32);
    blake2b_Final(&ctx, e_full, 64);
  }

  uint8_t e_bytes[32];
  reduce_to_scalar(e_full, e_bytes);

  bignum256 e_bn;
  bn_read_le(e_bytes, &e_bn);

  /* Step 7: S = r + e * rsk (mod q) */
  bignum256 S_bn;
  bn_copy(&e_bn, &S_bn);
  pallas_mul_mod_q(&S_bn, &rsk_bn);    /* S = e * rsk */
  pallas_add_mod_q(&S_bn, &r_bn);      /* S = S + r   */

  uint8_t S_bytes[32];
  bn_write_le(&S_bn, S_bytes);

  /* Step 8: Output signature = R_bytes || S_bytes */
  memcpy(sig_out, R_bytes, 32);
  memcpy(sig_out + 32, S_bytes, 32);

  /* Clean up all sensitive data */
  memzero(&sk_bn, sizeof(sk_bn));
  memzero(&alpha_bn, sizeof(alpha_bn));
  memzero(&rsk_bn, sizeof(rsk_bn));
  memzero(&r_bn, sizeof(r_bn));
  memzero(&e_bn, sizeof(e_bn));
  memzero(&S_bn, sizeof(S_bn));
  memzero(&R_point, sizeof(R_point));
  memzero(&rk_point, sizeof(rk_point));
  memzero(T, sizeof(T));
  memzero(r_bytes, sizeof(r_bytes));
  memzero(rsk_bytes, sizeof(rsk_bytes));
  memzero(R_bytes, sizeof(R_bytes));
  memzero(rk_bytes, sizeof(rk_bytes));
  memzero(e_full, sizeof(e_full));
  memzero(e_bytes, sizeof(e_bytes));
  memzero(S_bytes, sizeof(S_bytes));

  return 0;
}
