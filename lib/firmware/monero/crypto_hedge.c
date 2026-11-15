/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
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

#include <string.h>

#include "crypto_internal.h"
#include "trezor/crypto/memzero.h"

const uint8_t xmr_inv_eight[32] = {
    0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61, 0xd0, 0xda, 0x1c,
    0x7d, 0xb3, 0x9d, 0xd3, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06};

static void put_le32(SHA3_CTX *k, size_t v) {
  uint8_t b[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16),
                  (uint8_t)(v >> 24)};
  keccak_Update(k, b, sizeof(b));
}

bool xmr_hedge_key(uint8_t out[32], const char *domain, const uint8_t *secret,
                   size_t secret_len, const uint8_t *transcript,
                   size_t transcript_len) {
  uint8_t dom[32] = {0};
  uint8_t rng[32];
  size_t dom_len;
  SHA3_CTX k;

  memzero(out, 32);
  if (domain == NULL || (secret == NULL && secret_len) ||
      (transcript == NULL && transcript_len)) {
    return false;
  }
  dom_len = strlen(domain);
  if (dom_len == 0 || dom_len > sizeof(dom)) return false;
  memcpy(dom, domain, dom_len);
  if (!xmr_crypto_rng32(rng)) {
    memzero(rng, sizeof(rng));
    return false;
  }
  keccak_256_Init(&k);
  keccak_Update(&k, dom, sizeof(dom));
  put_le32(&k, secret_len);
  if (secret_len) keccak_Update(&k, secret, secret_len);
  put_le32(&k, transcript_len);
  if (transcript_len) keccak_Update(&k, transcript, transcript_len);
  keccak_Update(&k, rng, sizeof(rng));
  keccak_Final(&k, out); /* wipes k */
  memzero(rng, sizeof(rng));
  return true;
}

void xmr_sc_hash(bignum256modm r, const uint8_t *d, size_t n) {
  uint8_t h[32];
  keccak_256(d, n, h);
  expand256_modm(r, h, sizeof(h));
  memzero(h, sizeof(h));
}

void xmr_sc_nonce(bignum256modm r, const uint8_t nk[32], uint8_t tag,
                  uint8_t idx, const uint8_t *T) {
  uint8_t buf[32 + 2 + 32];
  size_t n = 34;
  memcpy(buf, nk, 32);
  buf[32] = tag;
  buf[33] = idx;
  if (T) {
    memcpy(buf + 34, T, 32);
    n += 32;
  }
  xmr_sc_hash(r, buf, n);
  memzero(buf, sizeof(buf));
}

static void sc_sqn_mul(bignum256modm y, int n, const bignum256modm x) {
  while (n--) mul256_modm(y, y, y);
  mul256_modm(y, y, x);
}

void xmr_sc_invert(bignum256modm inv, const bignum256modm x) {
  static const uint8_t chain[][2] = {
      {126, 5}, {4, 3},  {5, 15}, {5, 15}, {4, 9}, {2, 3}, {5, 15},
      {4, 5},   {6, 5},  {3, 7},  {5, 15}, {5, 7}, {4, 3}, {5, 11},
      {6, 11},  {10, 9}, {4, 3},  {5, 3},  {5, 3}, {5, 9}, {4, 7},
      {6, 15},  {5, 11}, {3, 5},  {6, 15}, {3, 5}, {3, 3}};
  bignum256modm _10, _100, _11, _101, _111, _1001, _1011, _1111;
  mul256_modm(_10, x, x);
  mul256_modm(_100, _10, _10);
  mul256_modm(_11, _10, x);
  mul256_modm(_101, _10, _11);
  mul256_modm(_111, _10, _101);
  mul256_modm(_1001, _10, _111);
  mul256_modm(_1011, _10, _1001);
  mul256_modm(_1111, _100, _1011);
  mul256_modm(inv, _1111, x);
  for (size_t i = 0; i < sizeof(chain) / sizeof(chain[0]); i++) {
    const bignum256modm *m;
    switch (chain[i][1]) {
      case 3:
        m = &_11;
        break;
      case 5:
        m = &_101;
        break;
      case 7:
        m = &_111;
        break;
      case 9:
        m = &_1001;
        break;
      case 11:
        m = &_1011;
        break;
      default:
        m = &_1111;
        break;
    }
    sc_sqn_mul(inv, chain[i][0], *m);
  }
  memzero(_10, sizeof(_10));
  memzero(_100, sizeof(_100));
  memzero(_11, sizeof(_11));
  memzero(_101, sizeof(_101));
  memzero(_111, sizeof(_111));
  memzero(_1001, sizeof(_1001));
  memzero(_1011, sizeof(_1011));
  memzero(_1111, sizeof(_1111));
}

bool xmr_eq32(const uint8_t a[32], const uint8_t b[32]) {
  uint8_t d = 0;
  for (size_t i = 0; i < 32; i++) d |= (uint8_t)(a[i] ^ b[i]);
  return d == 0;
}

bool xmr_sc_load_canonical(bignum256modm r, const uint8_t b[32]) {
  uint8_t c[32];
  expand256_modm(r, b, 32);
  contract256_modm(c, r);
  bool ok = xmr_eq32(c, b);
  memzero(c, sizeof(c));
  return ok;
}
