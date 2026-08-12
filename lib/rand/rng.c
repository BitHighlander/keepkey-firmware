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

#include "keepkey/rand/rng.h"

#include "keepkey/rand/rng_health.h"

#include <stdbool.h>
#include <stdlib.h>

#include "trezor/crypto/rand.h"

#ifdef EMULATOR
#include "keepkey/emulator/emulator.h"
#endif

#ifndef EMULATOR
#include <libopencm3/cm3/common.h>
#include <libopencm3/stm32/memorymap.h>
#include <libopencm3/stm32/f2/rng.h>
#endif

/* random32() has two implementations selected by a build flag: the STM32
 * hardware RNG, and -- under EMULATOR -- the host OS CSPRNG. Neither is a
 * weak PRNG today, and the emulator branch deliberately aborts rather than
 * degrading to libc random().
 *
 * This assertion guards the *selection*, not either implementation. The
 * July 2026 COLDCARD incident was not a broken RNG: a board config left
 * the hardware-RNG macro defined-but-zero, the supporting library tested
 * only whether that macro was *defined* rather than enabled, and seed
 * generation silently used the wrong source for five years (~1,367 BTC
 * drained across 4,585 addresses). Nothing about the output looked wrong
 * -- the substituted generator passed every statistical test, it was just
 * seeded with ~40 bits -- so no amount of host-side entropy testing could
 * have caught it. Only the build configuration was wrong.
 *
 * The lesson is that "which RNG did we actually compile in" deserves a
 * check the build cannot silently get wrong. __arm__ comes from the
 * compiler's own target definition rather than from any board config or
 * CMake option, so a mistaken -DEMULATOR cannot satisfy both conditions:
 * firmware targeting the STM32 can only ever compile the RNG_DR path.
 * Hosted emulator builds (x86_64 / __aarch64__) are unaffected. */
#if defined(EMULATOR) && defined(__arm__)
#error \
    "EMULATOR selects the host-CSPRNG random32(); ARM firmware must use the STM32 hardware RNG"
#endif

/* The same lesson applied to the other RNG selection switch. trezor-crypto's
 * crypto/rand.c carries a zero-seeded LCG random32() under #ifndef
 * RAND_PLATFORM_INDEPENDENT, and rand.c is compiled into the trezorcrypto
 * library (deps/crypto/CMakeLists.txt). It is excluded today only because the
 * top-level CMakeLists defines that macro -- previously as "=0", which reads
 * like a disable but, against an #ifndef test, is an enable.
 *
 * Every target that links trezorcrypto also links kkrand, so a stale build
 * would currently hit a duplicate-symbol error on random32() rather than
 * silently take the LCG. That is an accident of the link graph, not a
 * guarantee: a future target linking trezorcrypto alone would build clean and
 * deterministic. Assert the macro instead of relying on either coincidence. */
#ifndef RAND_PLATFORM_INDEPENDENT
#error \
    "RAND_PLATFORM_INDEPENDENT must be defined; without it trezor-crypto compiles its insecure LCG random32()"
#endif

void reset_rng(void) {
#ifndef EMULATOR
  /* disable RNG */
  RNG_CR &= ~(RNG_CR_IE | RNG_CR_RNGEN);
  /* reset Seed/Clock/ error status */
  RNG_SR &= ~(RNG_SR_SEIS | RNG_SR_CEIS);
  /* reenable RNG */
  RNG_CR |= RNG_CR_IE | RNG_CR_RNGEN;
  /* this delay is required before rng data can be read */
  {
    uint32_t cnt = 5 /* microseconds */ * 20;
    while (cnt--) {
      __asm__("nop");
    }
  }

  // to be extra careful and heed the STM32F205xx Reference manual,
  // Section 20.3.1 we don't use the first random number generated after setting
  // the RNGEN bit in setup. Raw: this runs from inside the health machinery's
  // own recovery path, and a discarded sample is not key material.
  random32_raw();
#endif
}

#ifdef EMULATOR
/* Test-only source override, so a unit test can make the continuous test trip
 * on a KNOWN draw instead of waiting for a real generator to misbehave. There
 * is no way to prove "the triggering word never leaves random32()" without
 * being able to trigger it on purpose. Emulator builds only. */
static bool rng_raw_forced = false;
static uint8_t rng_raw_byte = 0;
void rng_force_raw_byte(bool on, uint8_t value) {
  rng_raw_forced = on;
  rng_raw_byte = value;
}
#endif

uint32_t random32_raw(void) {
#ifdef EMULATOR
  if (rng_raw_forced) return 0x01010101u * (uint32_t)rng_raw_byte;
#endif
#ifndef EMULATOR
  uint32_t rng_samples = 0, rng_sr_img;
  static uint32_t last = 0, new = 0;

  while (new == last) {
    /* Capture the RNG status register */
    rng_sr_img = RNG_SR;
    if ((rng_sr_img & (RNG_SR_SEIS | RNG_SR_CEIS)) == 0) {
      if (rng_sr_img & RNG_SR_DRDY) {
        new = RNG_DR;
      }
    } else if ((rng_sr_img & (RNG_SR_SECS | RNG_SR_CECS)) == 0) {
      /* Reset RNG interrupt status bits (SECS, CECS errors no longer exist) */
      RNG_SR &= ~(RNG_SR_SEIS | RNG_SR_CEIS);
    } else {
      /* RNG is not ready.  Allow few more samples for RNG to come back alive
       * before resetting */
      if (++rng_samples >= 100) {
        /* RNG in hang state.  Reset RNG */
        reset_rng();
        rng_samples = 0;
      }
    }
  }
  last = new;
  return new;
#else
  /* Emulator cryptography must use the host OS CSPRNG. emulatorRandom() is
   * backed by /dev/urandom on POSIX and BCryptGenRandom on Windows and aborts
   * the process on failure; never fall back to libc random(). */
  uint32_t v = 0;
  emulatorRandom(&v, sizeof(v));
  return v;
#endif
}

void random_buffer_raw(uint8_t* buf, size_t len) {
  uint32_t r = 0;
  for (size_t i = 0; i < len; i++) {
    if (i % 4 == 0) r = random32_raw();
    buf[i] = (r >> ((i % 4) * 8)) & 0xff;
  }
}

/* The checked default. Everything that does not explicitly ask for a raw draw
 * arrives here, including trezor-crypto's random_buffer() and random_uniform()
 * and therefore every cryptographic consumer inside deps/. */
uint32_t random32(void) {
  rng_health_require();
  const uint32_t v = random32_raw();
  /* Feed the CONTINUOUS test. Without this the boot-time 1 KiB verdict was the
   * only thing enforced on the default path, so a source that went degenerate
   * after the gate -- which is what the RCT and APT exist to notice -- kept
   * producing key material for the rest of the boot. Every checked draw now
   * participates, including the ones inside deps/.
   *
   * The word that TRIPS the test must not be returned. An earlier revision
   * observed and returned unconditionally, so only the NEXT draw aborted -- and
   * random_buffer() is built from four-byte draws, so a run tripping on the
   * final word handed the caller the whole degenerate buffer. For a RedPallas
   * nonce that is the disclosure this gate exists to prevent, delivered by the
   * gate itself. */
  if (!rng_health_observe((const uint8_t*)&v, sizeof(v))) {
    abort();
  }
  return v;
}

#if defined(EMULATOR) && !defined(__APPLE__)
/* trezor-crypto declares random_buffer() as a weak symbol so platforms can
 * supply their own. GNU/MinGW ld will NOT extract a weak definition from a
 * static archive to satisfy a strong reference (fsm.c/reset.c/storage.c),
 * which breaks the Linux .so and Windows .dll links. Provide a strong
 * definition here — identical to trezor-crypto's, built on our random32(),
 * so it inherits the check exactly as the weak one does.
 * macOS ld64 resolves the weak one fine, so it's left untouched there. */
void random_buffer(uint8_t* buf, size_t len) {
  uint32_t r = 0;
  for (size_t i = 0; i < len; i++) {
    if (i % 4 == 0) r = random32();
    buf[i] = (r >> ((i % 4) * 8)) & 0xff;
  }
}
#endif

/* Local, deliberately. This used to call trezor-crypto's random_uniform(),
 * which made kkrand depend on trezorcrypto -- and GNU ld resolves static
 * archives left-to-right in a single pass, so whether it linked came down to
 * which archive happened to be listed first. It resolved by accident until a
 * change removed the reference that had been dragging rand.o in early, and
 * then every ARM target failed on `undefined reference to random_uniform`.
 * Four lines of rejection sampling is not worth an inter-archive edge.
 *
 * Same rejection bound as trezor-crypto's, so the distribution is unchanged. */
static uint32_t uniform_below(uint32_t (*draw)(void), uint32_t n) {
  uint32_t x = 0, max = 0xFFFFFFFF - (0xFFFFFFFF % n);
  while ((x = draw()) >= max);
  return x / (max / n);
}

// I miss C++ templates sooo bad.
#define RANDOM_PERMUTE(BUFF, COUNT, DRAW)       \
  do {                                          \
    for (size_t i = (COUNT) - 1; i >= 1; i--) { \
      size_t j = uniform_below((DRAW), i + 1);  \
      typeof(*(BUFF)) t = (BUFF)[j];            \
      (BUFF)[j] = (BUFF)[i];                    \
      (BUFF)[i] = t;                            \
    }                                           \
  } while (0)

void random_permute_char(char* str, size_t len) {
  RANDOM_PERMUTE(str, len, random32);
}

/* The raw shuffle exists for memcmp_s()'s decoy ordering, and only for that.
 *
 * memcmp_s() filled its decoys with random_buffer_raw() but then shuffled them
 * with the checked permutation, which reintroduced the fatal health path into
 * the bootloader by the back door -- bootloader signature verification calls
 * memcmp_s(). The decoy ORDER is a timing-equalisation detail exactly like the
 * decoy CONTENT: nothing is protected by its unpredictability, and halting on
 * the PIN-compare path would itself be an oracle. */
void random_permute_char_raw(char* str, size_t len) {
  RANDOM_PERMUTE(str, len, random32_raw);
}

void random_permute_u16(uint16_t* buf, size_t count) {
  RANDOM_PERMUTE(buf, count, random32);
}

#undef RANDOM_PERMUTE
