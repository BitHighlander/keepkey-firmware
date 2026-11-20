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

/* The Monero crypto module's only source of randomness. It lives alone in
 * this file on purpose: firmware-unit defines its own xmr_crypto_rng32() to
 * replay recorded vectors, and the static-archive link then never pulls this
 * object into the test binary. Firmware and the emulator always link this
 * one; there is no hook to reach from a running device. */

#include "keepkey/firmware/monero/crypto.h"

#include "keepkey/rand/rng_health.h"

bool xmr_crypto_rng32(uint8_t out[32]) {
  return random_buffer_checked(out, 32);
}
