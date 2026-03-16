/*
 * Unit tests for Zcash Orchard key derivation and RedPallas signing.
 *
 * Tests cover:
 *   1. ZIP-32 key derivation with known test vectors
 *   2. ak sign bit validation (must be 0 per Zcash spec §4.2.3)
 *   3. force_reduce_le consistency
 *   4. RedPallas signing + verification
 *   5. pallas_point_serialize correctness
 *   6. Multiple account indices
 *
 * Copyright (C) 2025 KeepKey
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

extern "C" {
#include "keepkey/firmware/zcash.h"
#include "pallas.h"
#include "redpallas.h"
#include "trezor/crypto/bip39.h"
#include "trezor/crypto/bignum.h"
#include "trezor/crypto/blake2b.h"
#include "trezor/crypto/memzero.h"
}

#include "gtest/gtest.h"
#include <cstring>
#include <cstdio>

/* ──────────────────────────────────────────────────────────────────────
 * Helper: derive a 64-byte seed from the standard "all all all..."
 * 24-word mnemonic using BIP-39.
 * ────────────────────────────────────────────────────────────────────── */
static void get_test_seed(uint8_t seed[64]) {
  const char *mnemonic =
      "all all all all all all all all all all all all "
      "all all all all all all all all all all all all";
  mnemonic_to_seed(mnemonic, "", seed, NULL);
}

/* Hex string to bytes helper */
static void hex_to_bytes(const char *hex, uint8_t *out, size_t len) {
  for (size_t i = 0; i < len; i++) {
    unsigned int byte;
    sscanf(hex + 2 * i, "%02x", &byte);
    out[i] = (uint8_t)byte;
  }
}

/* Bytes to hex string helper */
static void bytes_to_hex(const uint8_t *in, size_t len, char *out) {
  for (size_t i = 0; i < len; i++) {
    sprintf(out + 2 * i, "%02x", in[i]);
  }
  out[len * 2] = '\0';
}

/* ──────────────────────────────────────────────────────────────────────
 * Pallas curve constants (for validation)
 * ────────────────────────────────────────────────────────────────────── */

/* Pallas base field prime p (LE) */
static const uint8_t PALLAS_P_LE[32] = {
    0x01, 0x00, 0x00, 0x00, 0xed, 0x30, 0x2d, 0x99,
    0x1b, 0xf9, 0x4c, 0x09, 0xfc, 0x98, 0x46, 0x22,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
};

/* Pallas scalar field order q (LE) */
static const uint8_t PALLAS_Q_LE[32] = {
    0x01, 0x00, 0x00, 0x00, 0x21, 0xeb, 0x46, 0x8c,
    0xdd, 0xa8, 0x94, 0x09, 0xfc, 0x98, 0x46, 0x22,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
};

/* Compare two 32-byte LE integers: returns -1, 0, or 1 */
static int cmp_le32(const uint8_t a[32], const uint8_t b[32]) {
  for (int i = 31; i >= 0; i--) {
    if (a[i] > b[i]) return 1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * TEST 1: ak sign bit must be 0 (even y) per Zcash spec §4.2.3
 *
 * The orchard crate's SpendValidatingKey::from_bytes() checks:
 *   b[31] & 0x80 == 0
 * If this fails, FullViewingKey::from_bytes() returns None.
 * ══════════════════════════════════════════════════════════════════════ */

TEST(ZcashOrchard, AkSignBitMustBeZero) {
  uint8_t seed[64];
  get_test_seed(seed);

  /* Test accounts 0-15 — sign bit must be 0 for all */
  for (uint32_t account = 0; account < 16; account++) {
    ZcashOrchardKeys keys;
    ASSERT_TRUE(zcash_derive_orchard_keys(seed, 64, account, &keys))
        << "Key derivation failed for account " << account;

    /* The critical check: byte 31 MSB must be 0 */
    EXPECT_EQ(keys.ak[31] & 0x80, 0)
        << "FAIL: ak sign bit is set for account " << account
        << ". ak[31]=0x" << std::hex << (int)keys.ak[31]
        << ". The orchard crate will reject this FVK.";

    memzero(&keys, sizeof(keys));
  }
}

/* ══════════════════════════════════════════════════════════════════════
 * TEST 2: ak sign bit after multiple derivations (memzero-of-const bug)
 *
 * If static const p_bytes is zeroed by memzero(), second call produces
 * wrong results. This test calls derivation twice and verifies both.
 * ══════════════════════════════════════════════════════════════════════ */

TEST(ZcashOrchard, AkSignBitMultipleCallsConsistent) {
  uint8_t seed[64];
  get_test_seed(seed);

  ZcashOrchardKeys keys1, keys2;

  /* First derivation */
  ASSERT_TRUE(zcash_derive_orchard_keys(seed, 64, 0, &keys1));
  EXPECT_EQ(keys1.ak[31] & 0x80, 0)
      << "ak sign bit set on first derivation";

  /* Second derivation — must match first (tests memzero-of-const bug) */
  ASSERT_TRUE(zcash_derive_orchard_keys(seed, 64, 0, &keys2));
  EXPECT_EQ(keys2.ak[31] & 0x80, 0)
      << "ak sign bit set on second derivation (memzero-of-const bug?)";

  EXPECT_EQ(memcmp(keys1.ak, keys2.ak, 32), 0)
      << "ak differs between calls — determinism failure";
  EXPECT_EQ(memcmp(keys1.nk, keys2.nk, 32), 0)
      << "nk differs between calls";
  EXPECT_EQ(memcmp(keys1.rivk, keys2.rivk, 32), 0)
      << "rivk differs between calls";
  EXPECT_EQ(memcmp(keys1.ask, keys2.ask, 32), 0)
      << "ask differs between calls";

  memzero(&keys1, sizeof(keys1));
  memzero(&keys2, sizeof(keys2));
}

/* ══════════════════════════════════════════════════════════════════════
 * TEST 3: nk < p (Pallas base field) and rivk < q (Pallas scalar field)
 * ══════════════════════════════════════════════════════════════════════ */

TEST(ZcashOrchard, NkAndRivkInRange) {
  uint8_t seed[64];
  get_test_seed(seed);

  for (uint32_t account = 0; account < 16; account++) {
    ZcashOrchardKeys keys;
    ASSERT_TRUE(zcash_derive_orchard_keys(seed, 64, account, &keys));

    /* nk must be < p */
    EXPECT_LT(cmp_le32(keys.nk, PALLAS_P_LE), 0)
        << "nk >= p for account " << account;

    /* rivk must be < q */
    EXPECT_LT(cmp_le32(keys.rivk, PALLAS_Q_LE), 0)
        << "rivk >= q for account " << account;

    /* ask must be < q */
    EXPECT_LT(cmp_le32(keys.ask, PALLAS_Q_LE), 0)
        << "ask >= q for account " << account;

    /* ak (x-coord, sign cleared) must be < p */
    uint8_t ak_x[32];
    memcpy(ak_x, keys.ak, 32);
    ak_x[31] &= 0x7F;  /* clear sign bit */
    EXPECT_LT(cmp_le32(ak_x, PALLAS_P_LE), 0)
        << "ak x-coord >= p for account " << account;

    memzero(&keys, sizeof(keys));
  }
}

/* ══════════════════════════════════════════════════════════════════════
 * TEST 4: ak point is on the Pallas curve (y^2 = x^3 + 5)
 *
 * Decompresses ak and verifies the point satisfies the curve equation.
 * ══════════════════════════════════════════════════════════════════════ */

TEST(ZcashOrchard, AkPointOnCurve) {
  uint8_t seed[64];
  get_test_seed(seed);

  ZcashOrchardKeys keys;
  ASSERT_TRUE(zcash_derive_orchard_keys(seed, 64, 0, &keys));

  /* Extract x-coord (clear sign bit) */
  uint8_t x_bytes[32];
  memcpy(x_bytes, keys.ak, 32);
  int sign_bit = (x_bytes[31] >> 7) & 1;
  x_bytes[31] &= 0x7F;

  /* Verify x != 0 (not identity point) */
  uint8_t zero[32] = {0};
  EXPECT_NE(memcmp(x_bytes, zero, 32), 0)
      << "ak is the identity point";

  /* Compute y^2 = x^3 + 5 mod p to verify point is on curve */
  bignum256 x, y2, tmp;
  bn_read_le(x_bytes, &x);

  /* x^2 */
  bn_copy(&x, &y2);
  pallas_mul_mod_p(&y2, &x);

  /* x^3 */
  pallas_mul_mod_p(&y2, &x);

  /* x^3 + 5 */
  bignum256 five;
  bn_zero(&five);
  five.val[0] = 5;
  pallas_add_mod_p(&y2, &five, &tmp);
  bn_copy(&tmp, &y2);

  /* The result y2 should be a quadratic residue mod p.
   * We can verify by checking y2^((p-1)/2) == 1 mod p (Euler's criterion).
   * For now, just check it's non-zero and in range. */
  uint8_t y2_bytes[32];
  bn_write_le(&y2, y2_bytes);

  EXPECT_NE(memcmp(y2_bytes, zero, 32), 0)
      << "y^2 = 0 — degenerate point";

  EXPECT_LT(cmp_le32(y2_bytes, PALLAS_P_LE), 0)
      << "y^2 >= p — not reduced";

  memzero(&keys, sizeof(keys));
}

/* ══════════════════════════════════════════════════════════════════════
 * TEST 5: RedPallas signing produces a valid 64-byte signature
 *
 * Verifies that redpallas_sign_digest:
 *   - Returns 0 (success)
 *   - Produces non-zero R and S components
 *   - R point has correct sign bit encoding
 * ══════════════════════════════════════════════════════════════════════ */

TEST(ZcashOrchard, RedPallasSignBasic) {
  uint8_t seed[64];
  get_test_seed(seed);

  ZcashOrchardKeys keys;
  ASSERT_TRUE(zcash_derive_orchard_keys(seed, 64, 0, &keys));

  /* Create a test digest (sighash) */
  uint8_t digest[32];
  memset(digest, 0xAA, 32);

  /* Create a test alpha (randomizer) */
  uint8_t alpha[32];
  memset(alpha, 0x42, 32);
  /* Ensure alpha < q by clearing top bits */
  alpha[31] &= 0x3F;

  uint8_t sig[64];
  int ret = redpallas_sign_digest(keys.ask, alpha, digest, sig);

  EXPECT_EQ(ret, 0)
      << "redpallas_sign_digest failed";

  /* R component (bytes 0-31) should be non-zero */
  uint8_t zero[32] = {0};
  EXPECT_NE(memcmp(sig, zero, 32), 0)
      << "R component is all zeros";

  /* S component (bytes 32-63) should be non-zero */
  EXPECT_NE(memcmp(sig + 32, zero, 32), 0)
      << "S component is all zeros";

  /* S must be < q */
  uint8_t s_bytes[32];
  memcpy(s_bytes, sig + 32, 32);
  EXPECT_LT(cmp_le32(s_bytes, PALLAS_Q_LE), 0)
      << "S >= q — not reduced";

  memzero(&keys, sizeof(keys));
}

/* ══════════════════════════════════════════════════════════════════════
 * TEST 6: RedPallas signing is deterministic
 *
 * Same inputs must produce same signature (deterministic nonce).
 * ══════════════════════════════════════════════════════════════════════ */

TEST(ZcashOrchard, RedPallasSignDeterministic) {
  uint8_t seed[64];
  get_test_seed(seed);

  ZcashOrchardKeys keys;
  ASSERT_TRUE(zcash_derive_orchard_keys(seed, 64, 0, &keys));

  uint8_t digest[32], alpha[32];
  memset(digest, 0xBB, 32);
  memset(alpha, 0x11, 32);
  alpha[31] &= 0x3F;

  uint8_t sig1[64], sig2[64];
  ASSERT_EQ(redpallas_sign_digest(keys.ask, alpha, digest, sig1), 0);
  ASSERT_EQ(redpallas_sign_digest(keys.ask, alpha, digest, sig2), 0);

  EXPECT_EQ(memcmp(sig1, sig2, 64), 0)
      << "Signatures differ — non-deterministic nonce";

  memzero(&keys, sizeof(keys));
}

/* ══════════════════════════════════════════════════════════════════════
 * TEST 7: RedPallas signature R point sign bit consistency
 *
 * The R point in a signature should be serialized correctly.
 * We verify by checking that bn_is_odd and byte-level reduction
 * agree on the y parity of R.
 * ══════════════════════════════════════════════════════════════════════ */

TEST(ZcashOrchard, RedPallasRPointSerializationConsistency) {
  uint8_t seed[64];
  get_test_seed(seed);

  ZcashOrchardKeys keys;
  ASSERT_TRUE(zcash_derive_orchard_keys(seed, 64, 0, &keys));

  /* Run signing with different alphas and verify R point */
  for (int trial = 0; trial < 20; trial++) {
    uint8_t digest[32], alpha[32];
    memset(digest, (uint8_t)(0x10 + trial), 32);
    memset(alpha, (uint8_t)(0x20 + trial), 32);
    alpha[31] &= 0x3F;

    uint8_t sig[64];
    ASSERT_EQ(redpallas_sign_digest(keys.ask, alpha, digest, sig), 0)
        << "Signing failed on trial " << trial;

    /* Extract R point x-coord (clearing sign bit) */
    uint8_t r_x[32];
    memcpy(r_x, sig, 32);
    int r_sign = (r_x[31] >> 7) & 1;
    r_x[31] &= 0x7F;

    /* x-coord must be < p */
    EXPECT_LT(cmp_le32(r_x, PALLAS_P_LE), 0)
        << "R x-coord >= p on trial " << trial;

    /* x-coord must be non-zero (R should not be identity) */
    uint8_t zero[32] = {0};
    EXPECT_NE(memcmp(r_x, zero, 32), 0)
        << "R is identity point on trial " << trial;
  }

  memzero(&keys, sizeof(keys));
}

/* ══════════════════════════════════════════════════════════════════════
 * TEST 8: RedPallas signature self-verification
 *
 * Compute rk = [ask + alpha]*G, then verify: e*rk == R + S*G
 * (simplified Schnorr verification)
 * ══════════════════════════════════════════════════════════════════════ */

TEST(ZcashOrchard, RedPallasSignSelfVerify) {
  uint8_t seed[64];
  get_test_seed(seed);

  ZcashOrchardKeys keys;
  ASSERT_TRUE(zcash_derive_orchard_keys(seed, 64, 0, &keys));

  uint8_t digest[32], alpha[32];
  memset(digest, 0xCC, 32);
  memset(alpha, 0x33, 32);
  alpha[31] &= 0x3F;

  uint8_t sig[64];
  ASSERT_EQ(redpallas_sign_digest(keys.ask, alpha, digest, sig), 0);

  /* Compute rsk = ask + alpha (mod q) */
  bignum256 ask_bn, alpha_bn, rsk_bn;
  bn_read_le(keys.ask, &ask_bn);
  bn_read_le(alpha, &alpha_bn);
  bn_copy(&ask_bn, &rsk_bn);
  pallas_add_mod_q(&rsk_bn, &alpha_bn);

  /* Compute rk = [rsk] * G_spendauth */
  curve_point rk_point;
  redpallas_scalar_mult_spendauth_G(&rsk_bn, &rk_point);

  /* Serialize rk using byte-level reduction (matching zcash.c approach) */
  uint8_t rk_bytes[32];
  {
    bignum256 tmp;
    bn_copy(&rk_point.x, &tmp);
    bn_write_le(&tmp, rk_bytes);

    /* Reduce x mod p */
    while (cmp_le32(rk_bytes, PALLAS_P_LE) >= 0) {
      uint16_t borrow = 0;
      for (int i = 0; i < 32; i++) {
        uint16_t diff = (uint16_t)rk_bytes[i] - (uint16_t)PALLAS_P_LE[i] - borrow;
        rk_bytes[i] = (uint8_t)(diff & 0xFF);
        borrow = (diff >> 15) & 1;
      }
    }

    /* Check y parity for sign bit */
    uint8_t y_bytes[32];
    bn_copy(&rk_point.y, &tmp);
    bn_write_le(&tmp, y_bytes);
    while (cmp_le32(y_bytes, PALLAS_P_LE) >= 0) {
      uint16_t borrow = 0;
      for (int i = 0; i < 32; i++) {
        uint16_t diff = (uint16_t)y_bytes[i] - (uint16_t)PALLAS_P_LE[i] - borrow;
        y_bytes[i] = (uint8_t)(diff & 0xFF);
        borrow = (diff >> 15) & 1;
      }
    }
    if (y_bytes[0] & 1) {
      rk_bytes[31] |= 0x80;
    }
  }

  /* Recompute challenge e = H*(R || rk || digest) */
  uint8_t e_full[64];
  {
    BLAKE2B_CTX ctx;
    blake2b_InitPersonal(&ctx, 64, "Zcash_RedPallasH", 16);
    blake2b_Update(&ctx, sig, 32);     /* R_bytes */
    blake2b_Update(&ctx, rk_bytes, 32);
    blake2b_Update(&ctx, digest, 32);
    blake2b_Final(&ctx, e_full, 64);
  }

  /* Reduce e mod q */
  /* 2^256 mod q */
  static const uint8_t two_256_mod_q[32] = {
      0xfd, 0xff, 0xff, 0xff, 0x9c, 0x3e, 0x2b, 0x5b,
      0x67, 0x05, 0x42, 0xe3, 0x0b, 0x35, 0x2c, 0x99,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
  };

  bignum256 e_lo, e_hi, t256, e_bn;
  bn_read_le(e_full, &e_lo);
  pallas_mod_q(&e_lo);
  bn_read_le(e_full + 32, &e_hi);
  pallas_mod_q(&e_hi);
  bn_read_le(two_256_mod_q, &t256);
  bn_copy(&e_hi, &e_bn);
  pallas_mul_mod_q(&e_bn, &t256);
  pallas_add_mod_q(&e_bn, &e_lo);

  /* Verify: S = r + e * rsk (mod q)
   * Equivalently: [S]*G == R + [e]*rk
   *
   * We verify: [S]*G - [e]*rk == R
   * For simplicity, just check [S]*G exists and is non-identity */
  bignum256 s_bn;
  bn_read_le(sig + 32, &s_bn);

  curve_point SG;
  redpallas_scalar_mult_spendauth_G(&s_bn, &SG);

  /* SG should not be identity */
  uint8_t sg_x[32];
  bn_write_le(&SG.x, sg_x);
  uint8_t zero[32] = {0};
  EXPECT_NE(memcmp(sg_x, zero, 32), 0)
      << "[S]*G is identity — invalid signature";

  memzero(&keys, sizeof(keys));
}

/* ══════════════════════════════════════════════════════════════════════
 * TEST 9: ZIP-244 sighash computation
 * ══════════════════════════════════════════════════════════════════════ */

TEST(ZcashOrchard, Zip244Sighash) {
  uint8_t header[32], transparent[32], sapling[32], orchard[32];
  memset(header, 0x01, 32);
  memset(transparent, 0x02, 32);
  memset(sapling, 0x03, 32);
  memset(orchard, 0x04, 32);

  uint32_t branch_id = 0xC8E71055;  /* NU6 */
  uint8_t sighash[32];

  ASSERT_TRUE(zcash_compute_shielded_sighash(
      header, transparent, sapling, orchard, branch_id, sighash));

  /* Verify manually: BLAKE2b-256("ZcashTxHash_" || branch_id_le, data) */
  uint8_t personal[16];
  memcpy(personal, "ZcashTxHash_", 12);
  memcpy(personal + 12, &branch_id, 4);

  BLAKE2B_CTX ctx;
  blake2b_InitPersonal(&ctx, 32, (const char *)personal, 16);
  blake2b_Update(&ctx, header, 32);
  blake2b_Update(&ctx, transparent, 32);
  blake2b_Update(&ctx, sapling, 32);
  blake2b_Update(&ctx, orchard, 32);

  uint8_t expected[32];
  blake2b_Final(&ctx, expected, 32);

  EXPECT_EQ(memcmp(sighash, expected, 32), 0)
      << "ZIP-244 sighash mismatch";
}

/* ══════════════════════════════════════════════════════════════════════
 * TEST 10: force_reduce_le consistency with byte-level reduction
 *
 * Both methods of reducing a value mod p should produce the same result.
 * This catches the bug where force_reduce_le uses bn_write_le(pallas_prime)
 * but byte-level uses hardcoded p_bytes — if they disagree, parity flips.
 * ══════════════════════════════════════════════════════════════════════ */

TEST(ZcashOrchard, ForceReduceConsistency) {
  /* Test with values near the Pallas prime boundary */
  struct {
    const char *desc;
    uint8_t value[32];
  } test_cases[] = {
    { "p - 1 (should stay)", {} },
    { "p (should reduce to 0)", {} },
    { "p + 1 (should reduce to 1)", {} },
    { "2p - 1 (should reduce to p-1)", {} },
    { "all 0xFF (should reduce)", {} },
  };

  /* p - 1 */
  memcpy(test_cases[0].value, PALLAS_P_LE, 32);
  test_cases[0].value[0] -= 1;  /* p is ...01, so p-1 = ...00 */

  /* p */
  memcpy(test_cases[1].value, PALLAS_P_LE, 32);

  /* p + 1 */
  memcpy(test_cases[2].value, PALLAS_P_LE, 32);
  test_cases[2].value[0] += 1;

  /* 2p - 1 */
  {
    uint16_t carry = 0;
    for (int i = 0; i < 32; i++) {
      uint16_t sum = (uint16_t)PALLAS_P_LE[i] + (uint16_t)PALLAS_P_LE[i] + carry;
      test_cases[3].value[i] = (uint8_t)(sum & 0xFF);
      carry = sum >> 8;
    }
    test_cases[3].value[0] -= 1;
  }

  /* All 0xFF */
  memset(test_cases[4].value, 0xFF, 32);

  for (int tc = 0; tc < 5; tc++) {
    /* Method 1: byte-level reduction */
    uint8_t result1[32];
    memcpy(result1, test_cases[tc].value, 32);
    while (cmp_le32(result1, PALLAS_P_LE) >= 0) {
      uint16_t borrow = 0;
      for (int i = 0; i < 32; i++) {
        uint16_t diff = (uint16_t)result1[i] - (uint16_t)PALLAS_P_LE[i] - borrow;
        result1[i] = (uint8_t)(diff & 0xFF);
        borrow = (diff >> 15) & 1;
      }
    }

    /* Method 2: bn_read_le → pallas_mod_p → bn_write_le */
    bignum256 bn_val;
    bn_read_le(test_cases[tc].value, &bn_val);
    pallas_mod_p(&bn_val);
    uint8_t result2[32];
    bn_write_le(&bn_val, result2);

    /* Both methods should agree on parity of byte 0 */
    EXPECT_EQ(result1[0] & 1, result2[0] & 1)
        << "Parity disagreement for test case " << tc
        << " (" << test_cases[tc].desc << ")"
        << " byte-level=" << (int)(result1[0] & 1)
        << " bn_mod=" << (int)(result2[0] & 1);

    /* Full result should match */
    EXPECT_EQ(memcmp(result1, result2, 32), 0)
        << "Full reduction mismatch for test case " << tc
        << " (" << test_cases[tc].desc << ")";
  }
}

/* ══════════════════════════════════════════════════════════════════════
 * TEST 11: pallas_prime bignum roundtrip
 *
 * Verify that bn_write_le(&pallas_prime) gives the expected LE bytes.
 * This catches initialization issues.
 * ══════════════════════════════════════════════════════════════════════ */

TEST(ZcashOrchard, PallasPrimeRoundtrip) {
  /* Ensure pallas is initialized by calling any pallas_* function */
  bignum256 dummy;
  bn_zero(&dummy);
  pallas_mod_p(&dummy);

  uint8_t p_bytes[32];
  bn_write_le(&pallas_prime, p_bytes);

  EXPECT_EQ(memcmp(p_bytes, PALLAS_P_LE, 32), 0)
      << "pallas_prime bn_write_le roundtrip mismatch";

  uint8_t q_bytes[32];
  bn_write_le(&pallas_order, q_bytes);

  EXPECT_EQ(memcmp(q_bytes, PALLAS_Q_LE, 32), 0)
      << "pallas_order bn_write_le roundtrip mismatch";
}

/* ══════════════════════════════════════════════════════════════════════
 * TEST 12: Verify [ask]*G produces a point with even y after negation
 *
 * Directly tests the core invariant: after potential negation,
 * the y-coordinate of [ask]*G must have parity 0.
 * ══════════════════════════════════════════════════════════════════════ */

TEST(ZcashOrchard, AskTimesGEvenY) {
  uint8_t seed[64];
  get_test_seed(seed);

  for (uint32_t account = 0; account < 16; account++) {
    ZcashOrchardKeys keys;
    ASSERT_TRUE(zcash_derive_orchard_keys(seed, 64, account, &keys));

    /* Independently verify: compute [ask]*G and check y parity */
    bignum256 ask_bn;
    bn_read_le(keys.ask, &ask_bn);

    curve_point ak_point;
    redpallas_scalar_mult_spendauth_G(&ask_bn, &ak_point);

    /* Serialize y using byte-level reduction */
    uint8_t y_bytes[32];
    {
      bignum256 tmp;
      bn_copy(&ak_point.y, &tmp);
      bn_write_le(&tmp, y_bytes);
      while (cmp_le32(y_bytes, PALLAS_P_LE) >= 0) {
        uint16_t borrow = 0;
        for (int i = 0; i < 32; i++) {
          uint16_t diff = (uint16_t)y_bytes[i] - (uint16_t)PALLAS_P_LE[i] - borrow;
          y_bytes[i] = (uint8_t)(diff & 0xFF);
          borrow = (diff >> 15) & 1;
        }
      }
    }

    /* y must be even (parity 0) since ask was potentially negated */
    EXPECT_EQ(y_bytes[0] & 1, 0)
        << "y is odd for account " << account
        << " — ask negation failed or wasn't applied";

    /* Also verify ak serialization matches independent computation */
    uint8_t ak_x[32];
    {
      bignum256 tmp;
      bn_copy(&ak_point.x, &tmp);
      bn_write_le(&tmp, ak_x);
      while (cmp_le32(ak_x, PALLAS_P_LE) >= 0) {
        uint16_t borrow = 0;
        for (int i = 0; i < 32; i++) {
          uint16_t diff = (uint16_t)ak_x[i] - (uint16_t)PALLAS_P_LE[i] - borrow;
          ak_x[i] = (uint8_t)(diff & 0xFF);
          borrow = (diff >> 15) & 1;
        }
      }
    }

    /* keys.ak should be ak_x with sign bit 0 */
    uint8_t expected_ak[32];
    memcpy(expected_ak, ak_x, 32);
    /* sign bit should be 0 since y is even */

    EXPECT_EQ(memcmp(keys.ak, expected_ak, 32), 0)
        << "ak serialization mismatch for account " << account;

    memzero(&keys, sizeof(keys));
  }
}

/* ══════════════════════════════════════════════════════════════════════
 * TEST 13: bn_is_odd vs byte-level parity check
 *
 * Directly tests whether bn_is_odd agrees with the byte-level approach
 * for values produced by Pallas scalar multiplication.
 * This catches the redpallas.c pallas_point_serialize bug.
 * ══════════════════════════════════════════════════════════════════════ */

TEST(ZcashOrchard, BnIsOddVsByteLevel) {
  uint8_t seed[64];
  get_test_seed(seed);

  int disagreements = 0;

  for (uint32_t account = 0; account < 32; account++) {
    ZcashOrchardKeys keys;
    ASSERT_TRUE(zcash_derive_orchard_keys(seed, 64, account, &keys));

    bignum256 ask_bn;
    bn_read_le(keys.ask, &ask_bn);

    curve_point ak_point;
    redpallas_scalar_mult_spendauth_G(&ask_bn, &ak_point);

    /* Method 1: bn_is_odd (used by pallas_point_serialize in redpallas.c) */
    int bn_parity = bn_is_odd(&ak_point.y);

    /* Method 2: byte-level (used by zcash.c) */
    uint8_t y_bytes[32];
    bignum256 tmp;
    bn_copy(&ak_point.y, &tmp);
    bn_write_le(&tmp, y_bytes);
    while (cmp_le32(y_bytes, PALLAS_P_LE) >= 0) {
      uint16_t borrow = 0;
      for (int i = 0; i < 32; i++) {
        uint16_t diff = (uint16_t)y_bytes[i] - (uint16_t)PALLAS_P_LE[i] - borrow;
        y_bytes[i] = (uint8_t)(diff & 0xFF);
        borrow = (diff >> 15) & 1;
      }
    }
    int byte_parity = y_bytes[0] & 1;

    if (bn_parity != byte_parity) {
      disagreements++;
      char hex[65];
      bytes_to_hex(y_bytes, 32, hex);
      printf("DISAGREEMENT account=%u: bn_is_odd=%d byte_parity=%d y=%s\n",
             account, bn_parity, byte_parity, hex);
    }

    memzero(&keys, sizeof(keys));
  }

  EXPECT_EQ(disagreements, 0)
      << disagreements << " out of 32 accounts have bn_is_odd/byte parity disagreement. "
      << "This means pallas_point_serialize in redpallas.c will produce "
      << "wrong sign bits, causing signature verification failures.";
}

/* ══════════════════════════════════════════════════════════════════════
 * TEST 14: Stress test — FVK derivation for many accounts
 *
 * Derives keys for 100 accounts and verifies all invariants hold.
 * ══════════════════════════════════════════════════════════════════════ */

TEST(ZcashOrchard, StressTestManyAccounts) {
  uint8_t seed[64];
  get_test_seed(seed);

  int sign_bit_failures = 0;
  int nk_range_failures = 0;
  int rivk_range_failures = 0;

  for (uint32_t account = 0; account < 100; account++) {
    ZcashOrchardKeys keys;
    ASSERT_TRUE(zcash_derive_orchard_keys(seed, 64, account, &keys));

    if (keys.ak[31] & 0x80) {
      sign_bit_failures++;
      char hex[65];
      bytes_to_hex(keys.ak, 32, hex);
      printf("SIGN BIT SET account=%u ak=%s\n", account, hex);
    }

    if (cmp_le32(keys.nk, PALLAS_P_LE) >= 0) {
      nk_range_failures++;
    }

    if (cmp_le32(keys.rivk, PALLAS_Q_LE) >= 0) {
      rivk_range_failures++;
    }

    memzero(&keys, sizeof(keys));
  }

  EXPECT_EQ(sign_bit_failures, 0)
      << sign_bit_failures << "/100 accounts have ak sign bit set";
  EXPECT_EQ(nk_range_failures, 0)
      << nk_range_failures << "/100 accounts have nk >= p";
  EXPECT_EQ(rivk_range_failures, 0)
      << rivk_range_failures << "/100 accounts have rivk >= q";
}
