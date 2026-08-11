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

/* Seed-time RNG self-test.
 *
 * WHAT THIS CATCHES, AND WHAT IT DOES NOT. Two different failures, two
 * different checks, and the difference matters enough to state up front:
 *
 *   rng_source_live()     -- the generator is the STM32 hardware peripheral
 *                            and that peripheral is enabled and producing.
 *   rng_health_analyze()  -- the output is not stuck or degenerate.
 *
 * Neither one detects a *healthy-looking generator with a tiny seed*. That
 * was the July 2026 COLDCARD failure: a board config left the hardware-RNG
 * macro defined-but-zero, a software PRNG was substituted, and it passed
 * every statistical test because that is what a CSPRNG does -- it was simply
 * seeded with ~40 bits. Recovering a 40-bit seed pool from output requires
 * searching it; by collision that is ~2^20 independent seedings. No amount of
 * sampling substitutes.
 *
 * What stops that failure here is upstream, in rng.c: two #error guards that
 * fail the *build* when the RNG source selection is wrong. rng_source_live()
 * is the runtime backstop for a future configuration that gets past them --
 * on a build where the hardware path was never enabled, RNG_CR_RNGEN reads
 * back clear and this refuses to produce a seed.
 *
 * The #ifndef EMULATOR below is not the kind of config macro this file exists
 * to distrust. rng.c asserts `#if defined(EMULATOR) && defined(__arm__)` is a
 * compile error, and __arm__ comes from the compiler's own target definition,
 * so ARM firmware always compiles the register path. There is no build of the
 * shipping firmware in which these checks are absent.
 */

#include "keepkey/rand/rng_health.h"

#include <string.h>

#include "trezor/crypto/memzero.h"
#include "trezor/crypto/rand.h"

#ifndef EMULATOR
#include <libopencm3/cm3/common.h>
#include <libopencm3/stm32/memorymap.h>
#include <libopencm3/stm32/f2/rng.h>
#endif

bool rng_source_live(void) {
#ifndef EMULATOR
  /* The peripheral clock being off reads back as a clear RNGEN, so this one
   * test covers both "never enabled" and "enabled then lost its clock". */
  if ((RNG_CR & RNG_CR_RNGEN) == 0) {
    return false;
  }

  /* Sticky seed/clock error. RNG_SR_SEIS means the noise source failed its
   * own continuous test; SEIS latches, so a transient fault is still visible
   * here even if the current sample looks fine. */
  if (RNG_SR & (RNG_SR_SEIS | RNG_SR_CEIS)) {
    return false;
  }

  /* Fresh data, bounded wait. random32() spins forever by design; a self-test
   * must be able to conclude "dead" rather than hang the device before the
   * user has been told anything. */
  uint32_t first = 0;
  bool have_first = false;
  for (uint32_t tries = 0; tries < 100000; tries++) {
    if (RNG_SR & RNG_SR_DRDY) {
      uint32_t sample = RNG_DR;
      if (!have_first) {
        first = sample;
        have_first = true;
      } else if (sample != first) {
        return true;
      }
    }
  }
  return false;
#else
  /* emulatorRandom() is the host OS CSPRNG and aborts the process on failure,
   * so reaching this line at all means it is working. */
  return true;
#endif
}

/* SP 800-90B 4.4.1, repetition count.
 *
 * Cutoff C = 1 + ceil(-log2(alpha) / H). With H = 8 bits per byte and
 * alpha = 2^-30: 1 + ceil(30/8) = 1 + 4 = 5. Fail on five identical
 * consecutive bytes.
 *
 * False positives on a good source: about len * 2^-32 for a run of five,
 * i.e. ~2.4e-7 over the 1024-byte sample. This gate blocks wallet creation,
 * so alpha is deliberately at the strict end of NIST's 2^-20..2^-40 range --
 * a spurious block is a support ticket, and they should be rare enough never
 * to become one. */
static bool rct_pass(const uint8_t *buf, size_t len) {
  if (len == 0) return false;

  uint8_t prev = buf[0];
  uint32_t run = 1;
  for (size_t i = 1; i < len; i++) {
    if (buf[i] == prev) {
      if (++run >= RNG_HEALTH_RCT_CUTOFF) return false;
    } else {
      prev = buf[i];
      run = 1;
    }
  }
  return true;
}

/* SP 800-90B 4.4.2, adaptive proportion.
 *
 * Count how many of the W-1 samples following a reference sample equal it.
 * Under an IID source with H = 8, that count is Binomial(511, 1/256), well
 * approximated by Poisson(lambda = 511/256 = 1.996). Tail probabilities:
 *
 *   P(X >= 15) ~ 3.9e-9      P(X >= 16) ~ 4.7e-10      alpha = 2^-30 ~ 9.3e-10
 *
 * so C = 16 is the smallest cutoff meeting alpha. (For the more familiar
 * alpha = 2^-20 the same derivation gives C = 13, which is the value in
 * NIST's published table -- a cross-check that this derivation is right.)
 *
 * Partial trailing windows are analyzed too: a shorter window can only
 * produce fewer matches, so applying the full-window cutoff to it is
 * conservative and never manufactures a failure. */
static bool apt_pass(const uint8_t *buf, size_t len) {
  for (size_t start = 0; start < len; start += RNG_HEALTH_APT_WINDOW) {
    size_t end = start + RNG_HEALTH_APT_WINDOW;
    if (end > len) end = len;

    const uint8_t ref = buf[start];
    uint32_t matches = 1;
    for (size_t i = start + 1; i < end; i++) {
      if (buf[i] == ref && ++matches >= RNG_HEALTH_APT_CUTOFF) return false;
    }
  }
  return true;
}

bool rng_health_analyze(const uint8_t *buf, size_t len) {
  if (buf == NULL || len == 0) return false;
  return rct_pass(buf, len) && apt_pass(buf, len);
}

bool rng_health_check(void) {
  if (!rng_source_live()) return false;

  uint8_t sample[RNG_HEALTH_SAMPLE_BYTES];
  random_buffer(sample, sizeof(sample));
  bool ok = rng_health_analyze(sample, sizeof(sample));
  memzero(sample, sizeof(sample));
  return ok;
}
