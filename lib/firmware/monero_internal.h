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

#ifndef KEEPKEY_FIRMWARE_MONERO_INTERNAL_H
#define KEEPKEY_FIRMWARE_MONERO_INTERNAL_H

/* Shared by the Monero sources; they are built with USE_MONERO=1. */
#include "monero/monero.h"

/* Hs(input): Keccak-256 reduced mod l. Scrubs its own hash state. */
void monero_hash_scalar(bignum256modm out, const uint8_t* input, size_t size);

/* b = reduce(node_key), a = Hs(b). False (both wiped) if either is zero. */
bool monero_wallet_secrets(const uint8_t node_key[32], bignum256modm spend,
                           bignum256modm view);

/* m = Hs("SubAddr\0" || a || LE32(major) || LE32(minor)). */
void monero_subaddress_scalar(bignum256modm out, const bignum256modm view,
                              uint32_t major, uint32_t minor);

/* False unless `encoded` is the canonical encoding of a point of prime
 * order other than the identity. */
bool monero_decode_public(ge25519* point, const uint8_t encoded[32]);

/* keys = spend public || view public of subaddress (major, minor); (0, 0) is
 * the primary address. False (keys wiped) if either is the identity. */
bool monero_address_keys(const bignum256modm spend, const bignum256modm view,
                         uint32_t major, uint32_t minor, uint8_t keys[64]);

typedef enum {
  MONERO_ADDRESS_STANDARD = 0,
  MONERO_ADDRESS_SUBADDRESS = 1,
  MONERO_ADDRESS_INTEGRATED = 2, /* standard keys plus an 8-byte payment ID */
} MoneroAddressKind;

/* base58 address for the network: 95 characters, 106 when integrated, NUL
 * terminated. capacity must exceed that. Clears `address` on failure. */
bool monero_encode_address(uint32_t network, MoneroAddressKind kind,
                           const uint8_t keys[64], const uint8_t* payment_id,
                           char* address, size_t capacity);

#endif
