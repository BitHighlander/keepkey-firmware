/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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

#ifndef RNG_H
#define RNG_H

#include <stdint.h>
#include <stdlib.h>

/// Reset the hardware random number generator
void reset_rng(void);

/* THE DEFAULT IS CHECKED.
 *
 * random32() -- and therefore trezor-crypto's random_buffer(), random_uniform()
 * and everything built on them -- consults the RNG health verdict and HALTS the
 * device rather than returning entropy from a generator that failed its
 * self-test. That is deliberately the path of least resistance: an earlier
 * revision gated a list of call sites instead, and the list could never be
 * complete. It missed the Orchard RedPallas signing nonce in the pinned crypto
 * submodule, where a repeated nonce discloses the spend authorization key --
 * a dependency we do not own and would have had to remember to audit forever.
 *
 * Because the dependency calls random32() through the same symbol, checking
 * here covers RedPallas, SecAESSTM32 masking and ECDSA blinding without
 * touching deps/ at all.
 *
 * The raw entries below skip that check. Reach for one ONLY when the draw is
 * not key material AND halting would be worse than proceeding:
 *
 *   - the health test itself, which would otherwise recurse into its own gate;
 *   - GetEntropy, the RNG audit interface -- gating it would block the very
 *     measurement that finds a failing source;
 *   - stack canaries, timer jitter, U2F channel ids and constant-time-compare
 *     decoys, whose unpredictability protects nothing and which run on paths
 *     (pre-display boot, the bootloader) that must stay recoverable.
 *
 * Using a raw entry is a decision. Naming it makes that decision visible in
 * review. */
uint32_t random32_raw(void);
void random_buffer_raw(uint8_t* buf, size_t len);

void random_permute_char(char* str, size_t len);
/// Shuffle with a RAW draw. Only for memcmp_s()'s decoy ordering, which is a
/// timing-equalisation detail and runs in the bootloader.
void random_permute_char_raw(char* str, size_t len);
void random_permute_u16(uint16_t* buf, size_t count);

#endif
