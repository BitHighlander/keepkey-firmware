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
/* Counts samples FOLLOWING the window reference, so this is NIST's inclusive
 * cutoff minus one. Exact tail P(X >= 16) = 3.891e-10 <= 2^-30 for
 * X ~ Binomial(511, 1/256). See the derivation in rng_health.c. */
#define RNG_HEALTH_APT_CUTOFF 16

/* Streaming health-test state. Constant size: there is deliberately no sample
 * buffer anywhere in this module. */
typedef struct {
  uint8_t rct_prev;
  uint8_t apt_ref;
  uint32_t rct_run;
  uint32_t apt_following;
  uint32_t apt_pos;
  uint32_t total;
  /* RCT and APT keep INDEPENDENT initialisation state. Sharing one flag let
   * the APT window boundary reset the repetition counter, so a run straddling
   * byte 512 went undetected. RCT is continuous over the whole stream; only
   * APT is windowed. */
  bool rct_started;
  bool apt_started;
  bool ok;
} RngHealthCtx;

void rng_health_init(RngHealthCtx* ctx);
void rng_health_update(RngHealthCtx* ctx, const uint8_t* buf, size_t len);
/// Wipes ctx. Returns false if any window failed or no data was seen.
bool rng_health_final(RngHealthCtx* ctx);

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
bool rng_health_analyze(const uint8_t* buf, size_t len);

/// The latched, boot-lifetime verdict on this device's generator.
///
/// The full gate -- rng_source_live() plus rng_health_analyze() over a freshly
/// drawn RNG_HEALTH_SAMPLE_BYTES sample -- runs ONCE, on first use, and the
/// answer is remembered. Every draw subsequently made through
/// random_buffer_checked() is folded into a continuous SP 800-90B test, and a
/// failure there latches the verdict to failed for the rest of the boot.
/// Recovery is a reboot, deliberately: a source that failed must not be retried
/// until it passes.
///
/// Use this where there is a natural error path to report on. Where key
/// material is being drawn, use random_buffer_checked() instead -- it consults
/// the same verdict and cannot be forgotten.
bool rng_health_check(void);

/// Draw \p len bytes of KEY MATERIAL.
///
/// Returns false, with \p buf zeroed, if the generator has not passed or has
/// since failed its self-test. This is the one place that fails closed: every
/// draw that becomes a key, a wrapping salt, a seed or a derivation path must
/// come through here rather than random_buffer(), so a new call site inherits
/// the check instead of having to remember one.
///
/// Draws that are NOT key material -- stack canaries, timer jitter, U2F channel
/// ids, constant-time-compare decoys, the device UUID -- deliberately do not
/// use this: they must not be able to halt the device, and nothing is protected
/// by their unpredictability.
bool random_buffer_checked(uint8_t* buf, size_t len);

/// random_buffer_checked() for the key-material paths that have no way to
/// report a failure to anyone. Warns and halts rather than proceeding with a
/// zeroed buffer, which is the same disposition storage_secMigrate() already
/// takes when secrets fail to decrypt.
void random_buffer_or_die(uint8_t* buf, size_t len);

#ifdef EMULATOR
/// Test-only: force the latched verdict. `false` stands in for a generator
/// that failed its self-test, which is otherwise unreachable from a host build;
/// `true` re-arms the continuous state.
void rng_health_force_verdict(bool passed);
#endif

#endif
