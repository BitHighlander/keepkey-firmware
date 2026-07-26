/**
 * Copyright (c) 2025 KeepKey
 *
 * RedPallas (re-randomized Schnorr) signature scheme for Zcash Orchard.
 *
 * IMPORTANT: All modular arithmetic uses pallas_mul_mod_p/q etc. from pallas.c.
 * The generic bn_multiply/bn_mod/bn_sqrt from bignum.c MUST NOT be used
 * because they assume primes in [2^256 - 2^224, 2^256], while the Pallas
 * prime is only ~2^254.
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

#include "redpallas.h"

#include <string.h>

#include "bignum.h"
#include "blake2b.h"
#include "ecdsa.h"
#include "memzero.h"
#include "pallas.h"
#include "pallas_ct.h"
#include "rand.h"

/*
 * Zcash Orchard SpendAuth basepoint.
 *
 * This is NOT the standard Pallas generator G = (-1 mod p, 2).
 * It is the hash-derived basepoint: GroupHash^P("z.cash:Orchard", "G")
 * as specified in ZIP-224 / the reddsa crate.
 *
 * Serialized as compressed Pallas point (LE x-coordinate, sign bit in MSB).
 * Source: reddsa-0.5.1 ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES constant.
 */
static const uint8_t pallas_spendauth_G_bytes[32] = {
    0x63, 0xc9, 0x75, 0xb8, 0x84, 0x72, 0x1a, 0x8d, 0x0c, 0xa1, 0x70,
    0x7b, 0xe3, 0x0c, 0x7f, 0x0c, 0x5f, 0x44, 0x5f, 0x3e, 0x7c, 0x18,
    0x8d, 0x3b, 0x06, 0xd6, 0xf1, 0x28, 0xb3, 0x23, 0x55, 0xb7,
};

/* Cached SpendAuth basepoint (lazy-initialized from compressed bytes) */
static curve_point spendauth_G_cache;
static int spendauth_G_initialized = 0;

/*
 * Pallas point serialization (Pasta encoding):
 * 32 bytes, little-endian x-coordinate, with the sign of y encoded
 * in the most significant bit of the last byte.
 *
 * sign(y) = y is odd (bit 0 of y)
 */

static void pallas_point_serialize(const curve_point* p, uint8_t out[32]) {
  bignum256 x_copy;
  bn_copy(&p->x, &x_copy);
  bn_write_le(&x_copy, out);
  if (bn_is_odd(&p->y)) {
    out[31] |= 0x80;
  }
}

static int pallas_point_deserialize(const uint8_t in[32], curve_point* p) {
  uint8_t buf[32];
  memcpy(buf, in, 32);
  /* Extract sign bit */
  int y_odd = (buf[31] >> 7) & 1;
  buf[31] &= 0x7f;

  /* Read x-coordinate (little-endian) */
  bn_read_le(buf, &p->x);

  /* Check x < prime */
  if (!bn_is_less(&p->x, &pallas_prime)) {
    return -1;
  }

  /* Compute y^2 = x^3 + 5 mod p using custom Pallas arithmetic */
  bignum256 y2;
  bn_copy(&p->x, &y2);
  pallas_mul_mod_p(&y2, &p->x); /* y2 = x^2 */
  pallas_mul_mod_p(&y2, &p->x); /* y2 = x^3 */
  bignum256 b;
  bn_zero(&b);
  b.val[0] = 5;
  pallas_add_mod_p(&y2, &b, &y2); /* y2 = x^3 + 5 mod p */

  /* Compute y = sqrt(y2) mod p using Tonelli-Shanks */
  bn_copy(&y2, &p->y);
  if (pallas_sqrt_mod_p(&p->y) != 0) {
    return -1; /* Not a valid point (y2 is not a QR) */
  }

  /* Verify sqrt is correct: check y^2 == y2 */
  bignum256 check;
  bn_copy(&p->y, &check);
  pallas_mul_mod_p(&check, &p->y); /* check = y^2 */

  /* Normalize both for comparison */
  bn_normalize(&check);
  bn_normalize(&y2);
  if (!bn_is_equal(&check, &y2)) {
    return -1; /* Not a valid point */
  }

  /* Fix sign of y */
  if (bn_is_odd(&p->y) != y_odd) {
    /* y = p - y */
    pallas_sub_mod_p(&pallas_prime, &p->y, &p->y);
  }

  return 0;
}

/*
 * Scalar multiplication by the SpendAuth basepoint.
 * Uses lazy initialization: decompresses the basepoint once, then caches it.
 *
 * res = k * G_spendauth
 */
static void pallas_scalar_mult_spendauth(const bignum256* k, curve_point* res) {
  if (!spendauth_G_initialized) {
    pallas_point_deserialize(pallas_spendauth_G_bytes, &spendauth_G_cache);
    spendauth_G_initialized = 1;
  }
  /* k is an authorization scalar or nonce on signing/derivation paths.  Keep
   * it on the fixed-schedule projective implementation; pallas_point_mult()
   * is the variable-time public-data API used by Sinsemilla verification. */
  pallas_ct_point_mult(k, &spendauth_G_cache, res);
}

static void pallas_scalar_mult_spendauth_public(const bignum256* k,
                                                curve_point* res) {
  if (!spendauth_G_initialized) {
    pallas_point_deserialize(pallas_spendauth_G_bytes, &spendauth_G_cache);
    spendauth_G_initialized = 1;
  }
  /* alpha is transmitted by the host and committed by the Orchard action.
   * This path must never be used with ask, rsk, a nonce, or another secret. */
  pallas_point_mult(k, &spendauth_G_cache, res);
}

/*
 * Public API: Scalar multiplication by SpendAuth basepoint.
 * For use by FVK export (ak = [ask]*G_spendauth).
 */
void redpallas_scalar_mult_spendauth_G(const bignum256* k, curve_point* res) {
  pallas_scalar_mult_spendauth(k, res);
}

/*
 * Constant: 2^256 mod q (Pallas scalar field order).
 *
 * q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
 * 2^256 mod q = 2^254 - 3*(q - 2^254)
 *            =
 * 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF992C350BE34205675B2B3E9CFFFFFFFD
 *
 * Stored as 32 bytes little-endian.
 * Source: pasta_curves Montgomery radix R for the Pallas scalar field (Fq).
 * Verified: R + 3*q == 2^256.
 */
static const uint8_t two_256_mod_q[32] = {
    0xfd, 0xff, 0xff, 0xff, 0x9c, 0x3e, 0x2b, 0x5b, 0x67, 0x05, 0x42,
    0xe3, 0x0b, 0x35, 0x2c, 0x99, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
};

/*
 * Wide reduction: reduce a 512-bit LE value mod Pallas scalar order q.
 *
 * Matches the orchard crate's pallas::Scalar::from_uniform_bytes():
 *   result = (lo + hi * 2^256) mod q
 *
 * where lo = input[0..31] and hi = input[32..63], both little-endian.
 *
 * This MUST be used instead of simple truncation (taking low 256 bits)
 * because the orchard crate verifies against from_uniform_bytes — the
 * values differ whenever hi != 0, which is ~100% of the time.
 */
static void pallas_from_uniform_bytes(const uint8_t input[64], bignum256* out) {
  bignum256 lo, hi, t256;

  bn_read_le(input, &lo);
  pallas_mod_q(&lo);

  bn_read_le(input + 32, &hi);
  pallas_mod_q(&hi);

  bn_read_le(two_256_mod_q, &t256);

  /* out = hi * (2^256 mod q) mod q */
  bn_copy(&hi, out);
  pallas_mul_mod_q(out, &t256);

  /* out = out + lo mod q */
  pallas_add_mod_q(out, &lo);

  memzero(&lo, sizeof(lo));
  memzero(&hi, sizeof(hi));
}

/*
 * RedPallas challenge hash:
 * H = BLAKE2b-512("Zcash_RedPallasH", R_bytes || rk_bytes || sighash)
 * Reduced to a scalar mod order using wide reduction (from_uniform_bytes).
 */
static void redpallas_hash_challenge(const uint8_t R_bytes[32],
                                     const uint8_t rk_bytes[32],
                                     const uint8_t sighash[32], bignum256* c) {
  uint8_t hash_out[64];
  BLAKE2B_CTX ctx;

  blake2b_InitPersonal(&ctx, 64, "Zcash_RedPallasH", 16);
  blake2b_Update(&ctx, R_bytes, 32);
  blake2b_Update(&ctx, rk_bytes, 32);
  blake2b_Update(&ctx, sighash, 32);
  blake2b_Final(&ctx, hash_out, 64);

  /* Wide reduction matching orchard crate's from_uniform_bytes */
  pallas_from_uniform_bytes(hash_out, c);

  memzero(hash_out, sizeof(hash_out));
}

typedef struct {
  redpallas_progress_callback callback;
  void* context;
  uint32_t base;
  uint32_t span;
} redpallas_progress_bridge;

static void redpallas_nonce_progress(uint32_t completed, uint32_t total,
                                     void* context) {
  redpallas_progress_bridge* bridge = (redpallas_progress_bridge*)context;
  bridge->callback(bridge->base + (bridge->span * completed) / total, 1000,
                   bridge->context);
}

static int redpallas_sign_with_rsk(
    const bignum256* rsk, const uint8_t rk_bytes[32], const uint8_t* sighash,
    uint8_t* sig_out, redpallas_progress_callback progress,
    void* progress_context, uint32_t progress_base, uint32_t progress_span) {
  bignum256 r, c, s;
  curve_point R_point;
  uint8_t R_bytes[32];

  /* Generate random nonce r */
  uint8_t rbuf[32];
  random_buffer(rbuf, 32);
  bn_read_le(rbuf, &r);
  pallas_ct_mod_q(&r);

  /* Ensure r is not zero without branching on the secret nonce. */
  pallas_ct_scalar_replace_zero_with_one(&r);

  /* R = [r]G_spendauth - nonce commitment */
  if (progress) {
    redpallas_progress_bridge bridge = {progress, progress_context,
                                        progress_base, progress_span};
    pallas_ct_point_mult_progress(&r, &spendauth_G_cache, &R_point,
                                  redpallas_nonce_progress, &bridge);
  } else {
    pallas_scalar_mult_spendauth(&r, &R_point);
  }
  pallas_point_serialize(&R_point, R_bytes);

  /* c = H("Zcash_RedPallasH", R || rk || sighash) mod order */
  redpallas_hash_challenge(R_bytes, rk_bytes, sighash, &c);

  /* S = r + c * rsk (mod order) */
  pallas_ct_mul_mod_q(&c, rsk); /* c = c * rsk mod order */
  bn_copy(&r, &s);
  pallas_ct_add_mod_q(&s, &c); /* s = r + c*rsk mod order */

  /* Output: R (32 bytes LE) || S (32 bytes LE) */
  memcpy(sig_out, R_bytes, 32);
  bn_write_le(&s, sig_out + 32);

  /* Clean up sensitive data */
  memzero(&r, sizeof(r));
  memzero(&c, sizeof(c));
  memzero(&s, sizeof(s));
  memzero(&R_point, sizeof(R_point));
  memzero(R_bytes, sizeof(R_bytes));
  memzero(rbuf, sizeof(rbuf));

  return 0;
}

int redpallas_sign_digest_for_rk(const uint8_t* ask, const uint8_t* alpha,
                                 const uint8_t* rk, const uint8_t* sighash,
                                 uint8_t* sig_out,
                                 redpallas_progress_callback progress,
                                 void* progress_context) {
  if (!ask || !alpha || !rk || !sighash || !sig_out) return -1;

  if (!spendauth_G_initialized) {
    if (pallas_point_deserialize(pallas_spendauth_G_bytes,
                                 &spendauth_G_cache) != 0) {
      return -1;
    }
    spendauth_G_initialized = 1;
  }

  bignum256 ask_scalar, alpha_scalar, rsk;
  if (progress) progress(0, 1000, progress_context);

  bn_read_le(ask, &ask_scalar);
  bn_read_le(alpha, &alpha_scalar);
  bn_copy(&ask_scalar, &rsk);
  pallas_ct_add_mod_q(&rsk, &alpha_scalar);

  const int result = redpallas_sign_with_rsk(
      &rsk, rk, sighash, sig_out, progress, progress_context, 0, 1000);
  memzero(&ask_scalar, sizeof(ask_scalar));
  memzero(&alpha_scalar, sizeof(alpha_scalar));
  memzero(&rsk, sizeof(rsk));
  return result;
}

int redpallas_derive_rk_from_ak(const uint8_t* ak, const uint8_t* alpha,
                                uint8_t* rk_out) {
  if (!ak || !alpha || !rk_out) return -1;

  curve_point ak_point, alpha_point, rk_point;
  bignum256 alpha_scalar;
  if (pallas_point_deserialize(ak, &ak_point) != 0) {
    return -1;
  }

  bn_read_le(alpha, &alpha_scalar);
  pallas_mod_q(&alpha_scalar);
  pallas_scalar_mult_spendauth_public(&alpha_scalar, &alpha_point);
  pallas_point_add(&ak_point, &alpha_point, &rk_point);
  pallas_point_serialize(&rk_point, rk_out);

  memzero(&alpha_scalar, sizeof(alpha_scalar));
  memzero(&ak_point, sizeof(ak_point));
  memzero(&alpha_point, sizeof(alpha_point));
  memzero(&rk_point, sizeof(rk_point));
  return 0;
}

int redpallas_sign_digest_with_ak(const uint8_t* ask, const uint8_t* ak,
                                  const uint8_t* alpha,
                                  const uint8_t* expected_rk,
                                  const uint8_t* sighash, uint8_t* sig_out,
                                  redpallas_progress_callback progress,
                                  void* progress_context) {
  if (!ask || !ak || !alpha || !expected_rk || !sighash || !sig_out) return -1;

  bignum256 ask_scalar, alpha_scalar, rsk;
  uint8_t rk_bytes[32];
  if (progress) progress(0, 1000, progress_context);

  if (redpallas_derive_rk_from_ak(ak, alpha, rk_bytes) != 0 ||
      memcmp(rk_bytes, expected_rk, sizeof(rk_bytes)) != 0) {
    memzero(rk_bytes, sizeof(rk_bytes));
    return -1;
  }
  if (progress) progress(100, 1000, progress_context);

  bn_read_le(ask, &ask_scalar);
  bn_read_le(alpha, &alpha_scalar);
  bn_copy(&ask_scalar, &rsk);
  pallas_ct_add_mod_q(&rsk, &alpha_scalar);

  int result = redpallas_sign_with_rsk(&rsk, rk_bytes, sighash, sig_out,
                                       progress, progress_context, 100, 900);
  memzero(&ask_scalar, sizeof(ask_scalar));
  memzero(&alpha_scalar, sizeof(alpha_scalar));
  memzero(&rsk, sizeof(rsk));
  memzero(rk_bytes, sizeof(rk_bytes));
  return result;
}

int redpallas_sign_digest(const uint8_t* ask, const uint8_t* alpha,
                          const uint8_t* sighash, uint8_t* sig_out) {
  bignum256 ask_scalar, alpha_scalar, rsk;
  curve_point rk_point;
  uint8_t rk_bytes[32];

  bn_read_le(ask, &ask_scalar);
  bn_read_le(alpha, &alpha_scalar);
  bn_copy(&ask_scalar, &rsk);
  pallas_ct_add_mod_q(&rsk, &alpha_scalar);

  /* Compatibility API: without a cached ak, derive rk from secret rsk. */
  pallas_scalar_mult_spendauth(&rsk, &rk_point);
  pallas_point_serialize(&rk_point, rk_bytes);
  int result = redpallas_sign_with_rsk(&rsk, rk_bytes, sighash, sig_out, NULL,
                                       NULL, 0, 1000);

  memzero(&ask_scalar, sizeof(ask_scalar));
  memzero(&alpha_scalar, sizeof(alpha_scalar));
  memzero(&rsk, sizeof(rsk));
  memzero(&rk_point, sizeof(rk_point));
  memzero(rk_bytes, sizeof(rk_bytes));
  return result;
}

int redpallas_verify_digest(const uint8_t* rk, const uint8_t* sighash,
                            const uint8_t* sig) {
  bignum256 c, s;
  curve_point R_point, rk_point, lhs, rhs, cR;

  /* Deserialize R from signature */
  if (pallas_point_deserialize(sig, &R_point) != 0) {
    return -1;
  }

  /* Read S from signature */
  bn_read_le(sig + 32, &s);
  if (!bn_is_less(&s, &pallas_order)) {
    return -2;
  }

  /* Deserialize rk */
  if (pallas_point_deserialize(rk, &rk_point) != 0) {
    return -3;
  }

  /* Recompute challenge: c = H("Zcash_RedPallasH", R || rk || sighash) */
  uint8_t R_bytes[32];
  pallas_point_serialize(&R_point, R_bytes);
  redpallas_hash_challenge(R_bytes, rk, sighash, &c);

  /* Verify: [S]G_spendauth == R + [c]rk */
  /* LHS: [S]G_spendauth */
  pallas_scalar_mult_spendauth(&s, &lhs);

  /* RHS: [c]rk + R */
  pallas_point_mult(&c, &rk_point, &cR);
  pallas_point_add(&cR, &R_point, &rhs);

  /* Compare (both should be normalized from our custom operations) */
  bn_normalize(&lhs.x);
  bn_normalize(&lhs.y);
  bn_normalize(&rhs.x);
  bn_normalize(&rhs.y);
  if (!bn_is_equal(&lhs.x, &rhs.x) || !bn_is_equal(&lhs.y, &rhs.y)) {
    return -4;
  }

  return 0;
}

int redpallas_derive_rk(const uint8_t* ask, const uint8_t* alpha,
                        uint8_t* rk_out) {
  bignum256 ask_scalar, alpha_scalar, rsk;
  curve_point rk_point;

  bn_read_le(ask, &ask_scalar);
  bn_read_le(alpha, &alpha_scalar);

  /* rsk = (ask + alpha) mod order */
  bn_copy(&ask_scalar, &rsk);
  pallas_ct_add_mod_q(&rsk, &alpha_scalar);

  /* rk = [rsk]G_spendauth */
  pallas_scalar_mult_spendauth(&rsk, &rk_point);
  pallas_point_serialize(&rk_point, rk_out);

  memzero(&ask_scalar, sizeof(ask_scalar));
  memzero(&alpha_scalar, sizeof(alpha_scalar));
  memzero(&rsk, sizeof(rsk));

  return 0;
}
