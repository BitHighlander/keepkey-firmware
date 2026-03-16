/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2025 KeepKey
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "keepkey/firmware/zcash.h"

#include <string.h>

#include "trezor/crypto/bignum.h"
#include "trezor/crypto/blake2b.h"
#include "trezor/crypto/hasher.h"
#include "trezor/crypto/memzero.h"
#include "pallas.h"
#include "redpallas.h"

/*
 * ZIP-32 Orchard key derivation.
 *
 * Master key:
 *   I = BLAKE2b-512("ZcashIP32Orchard", seed)
 *   sk = I[0..32], chain_code = I[32..64]
 *
 * Child derivation (hardened only):
 *   I = BLAKE2b-512("ZcashIP32Orchard", chain_code,
 *                    0x11 || sk || i_be)
 *   where 0x11 indicates hardened derivation with Orchard,
 *   and i_be is the 4-byte big-endian child index with the hardened bit set.
 *
 * From the spending key sk, subkeys are derived using PRF^expand:
 *   PRF^expand(sk, t) = BLAKE2b-512("Zcash_ExpandSeed", sk || t)
 *
 *   ask  = ToScalar(PRF^expand(sk, [0x06]))
 *   nk   = ToBase(PRF^expand(sk, [0x07]))
 *   rivk = ToScalar(PRF^expand(sk, [0x08]))
 *
 * ToScalar: interpret 64 bytes as LE integer, reduce mod order
 * ToBase: interpret 64 bytes as LE integer, reduce mod prime
 */

/* BLAKE2b-512 with personalization "ZcashIP32Orchard" */
static void zip32_orchard_blake2b(const uint8_t *key, size_t key_len,
                                  const uint8_t *data, size_t data_len,
                                  uint8_t out[64]) {
  BLAKE2B_CTX ctx;
  blake2b_InitPersonal(&ctx, 64, "ZcashIP32Orchard", 16);
  if (key != NULL && key_len > 0) {
    blake2b_Update(&ctx, key, key_len);
  }
  blake2b_Update(&ctx, data, data_len);
  blake2b_Final(&ctx, out, 64);
}

/* PRF^expand(sk, t) = BLAKE2b-512("Zcash_ExpandSeed", sk || t) */
static void prf_expand(const uint8_t sk[32], const uint8_t *t, size_t t_len,
                       uint8_t out[64]) {
  BLAKE2B_CTX ctx;
  blake2b_InitPersonal(&ctx, 64, "Zcash_ExpandSeed", 16);
  blake2b_Update(&ctx, sk, 32);
  blake2b_Update(&ctx, t, t_len);
  blake2b_Final(&ctx, out, 64);
}

/*
 * 2^256 mod q (Pallas scalar field order), little-endian.
 * q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
 * R = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF992C350BE34205675B2B3E9CFFFFFFFD
 * Verified: R + 3*q == 2^256.
 */
static const uint8_t two_256_mod_q[32] = {
    0xfd, 0xff, 0xff, 0xff, 0x9c, 0x3e, 0x2b, 0x5b,
    0x67, 0x05, 0x42, 0xe3, 0x0b, 0x35, 0x2c, 0x99,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
};

/*
 * 2^256 mod p (Pallas base field prime), little-endian.
 * p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
 * R = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF992C350BE41914AD34786D38FFFFFFFD
 * Verified: R + 3*p == 2^256.
 */
static const uint8_t two_256_mod_p[32] = {
    0xfd, 0xff, 0xff, 0xff, 0x38, 0x6d, 0x78, 0x34,
    0xad, 0x14, 0x19, 0xe4, 0x0b, 0x35, 0x2c, 0x99,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
};

/*
 * ToScalar: reduce a 512-bit LE integer mod Pallas scalar order.
 *
 * Uses wide reduction matching the orchard crate's from_uniform_bytes:
 *   result = (lo + hi * 2^256) mod q
 * where lo = input[0..31], hi = input[32..63] (little-endian).
 */
static void to_scalar(const uint8_t input[64], uint8_t output[32]) {
  bignum256 lo, hi, t256, result;

  bn_read_le(input, &lo);
  pallas_mod_q(&lo);

  bn_read_le(input + 32, &hi);
  pallas_mod_q(&hi);

  bn_read_le(two_256_mod_q, &t256);

  /* result = hi * (2^256 mod q) mod q */
  bn_copy(&hi, &result);
  pallas_mul_mod_q(&result, &t256);

  /* result = result + lo mod q */
  pallas_add_mod_q(&result, &lo);

  bn_write_le(&result, output);

  memzero(&lo, sizeof(lo));
  memzero(&hi, sizeof(hi));
  memzero(&result, sizeof(result));
}

/*
 * ToBase: reduce a 512-bit LE integer mod Pallas base field prime.
 *
 * Uses wide reduction:
 *   result = (lo + hi * 2^256) mod p
 * where lo = input[0..31], hi = input[32..63] (little-endian).
 */
static void to_base(const uint8_t input[64], uint8_t output[32]) {
  bignum256 lo, hi, t256, result;

  bn_read_le(input, &lo);
  pallas_mod_p(&lo);

  bn_read_le(input + 32, &hi);
  pallas_mod_p(&hi);

  bn_read_le(two_256_mod_p, &t256);

  /* result = hi * (2^256 mod p) mod p */
  bn_copy(&hi, &result);
  pallas_mul_mod_p(&result, &t256);

  /* result = result + lo mod p */
  bignum256 sum;
  pallas_add_mod_p(&result, &lo, &sum);
  bn_copy(&sum, &result);
  memzero(&sum, sizeof(sum));
  /* bn_mod may not fully reduce in one pass for Pallas prime (trezor-crypto
   * bignum256 internal representation can leave values > modulus after
   * add/multiply). Reduce repeatedly until result < p. */
  pallas_mod_p(&result);
  pallas_mod_p(&result);
  pallas_mod_p(&result);

  bn_write_le(&result, output);

  memzero(&lo, sizeof(lo));
  memzero(&hi, sizeof(hi));
  memzero(&result, sizeof(result));
}

/* Hardened child index */
#define ZIP32_HARDENED 0x80000000

bool zcash_derive_orchard_keys(const uint8_t *seed, uint32_t seed_len,
                               uint32_t account, ZcashOrchardKeys *keys) {
  uint8_t I[64];
  uint8_t sk[32], chain_code[32];

  /* Step 1: Master key from seed */
  zip32_orchard_blake2b(NULL, 0, seed, seed_len, I);
  memcpy(sk, I, 32);
  memcpy(chain_code, I + 32, 32);

  /* Step 2: Derive path m_orchard / 32' / 133' / account' */
  uint32_t path[3] = {
      32 | ZIP32_HARDENED,       /* Purpose (Orchard) */
      133 | ZIP32_HARDENED,      /* Coin type (Zcash) */
      account | ZIP32_HARDENED   /* Account */
  };

  for (int i = 0; i < 3; i++) {
    /* Child derivation:
     * I = BLAKE2b-512("ZcashIP32Orchard",
     *                  chain_code || 0x11 || sk || index_be)
     */
    uint8_t child_data[1 + 32 + 4];
    child_data[0] = 0x11;  /* Hardened Orchard derivation flag */
    memcpy(child_data + 1, sk, 32);
    /* Big-endian index */
    uint32_t idx = path[i];
    child_data[33] = (idx >> 24) & 0xff;
    child_data[34] = (idx >> 16) & 0xff;
    child_data[35] = (idx >> 8) & 0xff;
    child_data[36] = idx & 0xff;

    zip32_orchard_blake2b(chain_code, 32, child_data, sizeof(child_data), I);
    memcpy(sk, I, 32);
    memcpy(chain_code, I + 32, 32);

    memzero(child_data, sizeof(child_data));
  }

  /* Step 3: Derive subkeys from final spending key */
  memcpy(keys->sk, sk, 32);

  uint8_t expanded[64];

  /* ask = ToScalar(PRF^expand(sk, [0x06])) */
  uint8_t t_ask = 0x06;
  prf_expand(sk, &t_ask, 1, expanded);
  to_scalar(expanded, keys->ask);

  /*
   * Zcash spec (§ 4.2.3): If [ask]*G_spendauth has odd y (ỹ = 1),
   * negate ask so that the resulting ak always has ỹ = 0.
   * This matches the orchard crate's SpendAuthorizingKey::from() behavior.
   */
  {
    bignum256 ask_test;
    bn_read_le(keys->ask, &ask_test);
    curve_point ak_test;
    redpallas_scalar_mult_spendauth_G(&ask_test, &ak_test);
    if (bn_is_odd(&ak_test.y)) {
      /* ask = order - ask (negate mod q) */
      bignum256 neg_ask;
      bn_copy(&pallas_order, &neg_ask);
      bignum256 ask_val;
      bn_read_le(keys->ask, &ask_val);
      bn_normalize(&ask_val);
      bn_normalize(&neg_ask);
      /* neg_ask = order - ask */
      int32_t borrow = 0;
      for (int i = 0; i < 9; i++) {
        int32_t diff = (int32_t)neg_ask.val[i] - (int32_t)ask_val.val[i] + borrow;
        if (diff < 0) {
          diff += (1 << 29);
          borrow = -1;
        } else {
          borrow = 0;
        }
        neg_ask.val[i] = (uint32_t)diff;
      }
      bn_write_le(&neg_ask, keys->ask);
      memzero(&neg_ask, sizeof(neg_ask));
      memzero(&ask_val, sizeof(ask_val));
    }
    memzero(&ask_test, sizeof(ask_test));
    memzero(&ak_test, sizeof(ak_test));
  }

  /* nk = ToBase(PRF^expand(sk, [0x07])) */
  uint8_t t_nk = 0x07;
  prf_expand(sk, &t_nk, 1, expanded);
  to_base(expanded, keys->nk);

  /* rivk = ToScalar(PRF^expand(sk, [0x08])) */
  uint8_t t_rivk = 0x08;
  prf_expand(sk, &t_rivk, 1, expanded);
  to_scalar(expanded, keys->rivk);

  /* Clean up */
  memzero(I, sizeof(I));
  memzero(sk, sizeof(sk));
  memzero(chain_code, sizeof(chain_code));
  memzero(expanded, sizeof(expanded));

  return true;
}

bool zcash_compute_shielded_sighash(const uint8_t header_digest[32],
                                    const uint8_t transparent_digest[32],
                                    const uint8_t sapling_digest[32],
                                    const uint8_t orchard_digest[32],
                                    uint32_t branch_id,
                                    uint8_t sighash_out[32]) {
  Hasher h;
  uint8_t personal[16];

  memcpy(personal, "ZcashTxHash_", 12);
  memcpy(personal + 12, &branch_id, 4);

  hasher_InitParam(&h, HASHER_BLAKE2B_PERSONAL, personal, 16);
  hasher_Update(&h, header_digest, 32);
  hasher_Update(&h, transparent_digest, 32);
  hasher_Update(&h, sapling_digest, 32);
  hasher_Update(&h, orchard_digest, 32);
  hasher_Final(&h, sighash_out);

  return true;
}
