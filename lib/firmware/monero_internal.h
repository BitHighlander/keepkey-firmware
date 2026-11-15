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

#endif
