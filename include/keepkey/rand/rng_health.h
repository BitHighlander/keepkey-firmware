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

#ifndef KEEPKEY_RAND_RNG_HEALTH_H
#define KEEPKEY_RAND_RNG_HEALTH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bytes drawn for the seed-time self-test: two full APT windows. */
#define RNG_HEALTH_SAMPLE_BYTES 1024

/* SP 800-90B continuous-test parameters, derived for H = 8 bits/byte and
 * alpha = 2^-30. Both derivations are spelled out in rng_health.c so a
 * reviewer can recompute them rather than trust a copied table. */
#define RNG_HEALTH_RCT_CUTOFF 5
#define RNG_HEALTH_APT_WINDOW 512
#define RNG_HEALTH_APT_CUTOFF 16

/// Report which random32() implementation is actually running and whether it
/// is alive. On STM32 this reads the RNG peripheral's own control and status
/// registers; the answer does not depend on any build-configuration macro
/// having the value its name suggests. Returns false if the peripheral is
/// disabled, latching an error, or not producing fresh data.
///
/// SCOPE: detects an accidentally mis-built or dead generator. It is not an
/// attestation -- firmware that lies can return whatever it likes.
bool rng_source_live(void);

/// SP 800-90B repetition-count and adaptive-proportion tests over `buf`.
/// Pure function, no I/O: this is the unit-tested half.
///
/// SCOPE: catches a stuck or grossly degenerate source. A healthy-looking
/// generator with a tiny seed passes -- no output test detects that.
bool rng_health_analyze(const uint8_t *buf, size_t len);

/// Full seed-time gate: rng_source_live() plus rng_health_analyze() over a
/// freshly drawn RNG_HEALTH_SAMPLE_BYTES sample. Callers must refuse to
/// generate key material when this returns false.
bool rng_health_check(void);

#endif
