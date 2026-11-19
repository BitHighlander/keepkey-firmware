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

/* Helpers shared by crypto_bpp.c, crypto_clsag.c and crypto_hedge.c only. */

#ifndef KEEPKEY_FIRMWARE_MONERO_CRYPTO_INTERNAL_H
#define KEEPKEY_FIRMWARE_MONERO_CRYPTO_INTERNAL_H

#include "keepkey/firmware/monero/crypto.h"

/* 1/8 mod l, little endian. */
extern const uint8_t xmr_inv_eight[32];

/* r = Keccak256(d) mod l. The digest is wiped: use for secret inputs. */
void xmr_sc_hash(bignum256modm r, const uint8_t *d, size_t n);

/* r = Keccak256(nk || tag || idx || T) mod l, T may be NULL. Derives one
 * hedged nonce from a key made by xmr_hedge_key(). */
void xmr_sc_nonce(bignum256modm r, const uint8_t nk[32], uint8_t tag,
                  uint8_t idx, const uint8_t *T);

/* x^(l-2) by Monero's fixed addition chain (constant time). */
void xmr_sc_invert(bignum256modm inv, const bignum256modm x);

/* Loads 32 bytes; false if they are not the canonical encoding (< l). */
bool xmr_sc_load_canonical(bignum256modm r, const uint8_t b[32]);

/* Constant-time equality of 32 bytes. */
bool xmr_eq32(const uint8_t a[32], const uint8_t b[32]);

/* Defined in ed25519-donna-impl-base.c without a header declaration. */
void ge25519_move_conditional_pniels_array(ge25519_pniels *r,
                                           const ge25519_pniels *p, int pos,
                                           int n);

#endif
