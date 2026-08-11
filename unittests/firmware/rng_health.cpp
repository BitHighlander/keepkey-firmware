extern "C" {
#include "keepkey/rand/rng_health.h"
}

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

// Deterministic filler: an LCG is fine here because these vectors only need to
// be non-degenerate, not cryptographic. Using a fixed sequence keeps the test
// from being flaky on a bad draw.
std::vector<uint8_t> pseudo(size_t len, uint32_t seed = 1) {
  std::vector<uint8_t> v(len);
  uint32_t s = seed;
  for (size_t i = 0; i < len; i++) {
    s = s * 1664525u + 1013904223u;
    v[i] = static_cast<uint8_t>(s >> 24);
  }
  return v;
}

TEST(RngHealth, RejectsEmptyAndNull) {
  EXPECT_FALSE(rng_health_analyze(nullptr, 32));
  const uint8_t b = 0;
  EXPECT_FALSE(rng_health_analyze(&b, 0));
}

TEST(RngHealth, AcceptsNonDegenerateSample) {
  auto v = pseudo(RNG_HEALTH_SAMPLE_BYTES);
  EXPECT_TRUE(rng_health_analyze(v.data(), v.size()));
}

// A dead peripheral reading back a constant is the failure this exists for.
TEST(RngHealth, RejectsAllZeros) {
  std::vector<uint8_t> v(RNG_HEALTH_SAMPLE_BYTES, 0x00);
  EXPECT_FALSE(rng_health_analyze(v.data(), v.size()));
}

TEST(RngHealth, RejectsStuckHighByte) {
  std::vector<uint8_t> v(RNG_HEALTH_SAMPLE_BYTES, 0xFF);
  EXPECT_FALSE(rng_health_analyze(v.data(), v.size()));
}

// RCT boundary: cutoff is 5, so a run of 4 must pass and 5 must fail.
TEST(RngHealth, RctCutoffIsExact) {
  auto ok = pseudo(RNG_HEALTH_SAMPLE_BYTES, 7);
  for (int i = 0; i < RNG_HEALTH_RCT_CUTOFF - 1; i++) ok[100 + i] = 0xA5;
  // Neighbours must differ or the run is longer than intended.
  ok[99] = 0x11;
  ok[100 + RNG_HEALTH_RCT_CUTOFF - 1] = 0x22;
  EXPECT_TRUE(rng_health_analyze(ok.data(), ok.size()));

  auto bad = ok;
  for (int i = 0; i < RNG_HEALTH_RCT_CUTOFF; i++) bad[100 + i] = 0xA5;
  bad[100 + RNG_HEALTH_RCT_CUTOFF] = 0x22;
  EXPECT_FALSE(rng_health_analyze(bad.data(), bad.size()));
}

// APT boundary: 16 occurrences of the window's reference byte inside one
// 512-byte window fails; 15 passes. Spread them out so RCT stays quiet.
TEST(RngHealth, AptCutoffIsExact) {
  const uint8_t ref = 0x5A;

  auto build = [&](uint32_t extra) {
    auto v = pseudo(RNG_HEALTH_APT_WINDOW, 3);
    // Clear any incidental matches so the count is exactly what we plant.
    for (auto& b : v)
      if (b == ref) b = ref ^ 0x01;
    v[0] = ref;  // the window reference, which is NOT itself counted
    for (uint32_t i = 0; i < extra; i++) v[8 + i * 16] = ref;
    return v;
  };

  // The cutoff counts samples FOLLOWING the reference, so cutoff-1 following
  // matches must pass and exactly cutoff must fail.
  auto ok = build(RNG_HEALTH_APT_CUTOFF - 1);
  EXPECT_TRUE(rng_health_analyze(ok.data(), ok.size()));

  auto bad = build(RNG_HEALTH_APT_CUTOFF);
  EXPECT_FALSE(rng_health_analyze(bad.data(), bad.size()));
}

// THE LIMITATION, PINNED AS A TEST.
//
// This stream comes from a generator with a 16-bit seed -- only 65536 possible
// outputs in the whole universe of them -- and the health test passes it. That
// is not a bug to fix later; no output test detects a small internal state, and
// the Coldcard failure of July 2026 was this shape with ~40 bits. If someone
// ever "fixes" this expectation to EXPECT_FALSE, the check they added is
// measuring something other than what it claims.
//
// The defenses that do cover this live elsewhere: the #error build guards in
// lib/rand/rng.c and rng_source_live() in lib/rand/rng_health.c.
TEST(RngHealth, PassesTinySeedGeneratorByDesign) {
  auto v = pseudo(RNG_HEALTH_SAMPLE_BYTES, 0xBEEF);
  EXPECT_TRUE(rng_health_analyze(v.data(), v.size()));
}

// REGRESSION: RCT state must not reset at the APT window boundary. An earlier
// version shared one "started" flag between both tests, so the byte after each
// 512-sample window reset the run counter and a repeat spanning the boundary
// went unnoticed.
TEST(RngHealth, RctSpansAptWindowBoundary) {
  auto v = pseudo(RNG_HEALTH_SAMPLE_BYTES, 21);
  const size_t b = RNG_HEALTH_APT_WINDOW;  // first byte of the second window
  // Straddle the boundary: cutoff identical bytes ending just past it.
  for (size_t i = 0; i < RNG_HEALTH_RCT_CUTOFF; i++) v[b - 2 + i] = 0x7E;
  v[b - 3] = 0x11;
  v[b - 2 + RNG_HEALTH_RCT_CUTOFF] = 0x22;
  EXPECT_FALSE(rng_health_analyze(v.data(), v.size()));
}

// Chunked feeding must be identical to one-shot feeding, including at chunk
// sizes that do not divide the window.
TEST(RngHealth, IrregularChunkingMatchesOneShot) {
  auto v = pseudo(RNG_HEALTH_SAMPLE_BYTES, 33);
  const size_t b = RNG_HEALTH_APT_WINDOW;
  for (size_t i = 0; i < RNG_HEALTH_RCT_CUTOFF; i++) v[b - 2 + i] = 0x5C;
  v[b - 3] = 0x11;
  v[b - 2 + RNG_HEALTH_RCT_CUTOFF] = 0x22;

  for (size_t chunk : {size_t(1), size_t(7), size_t(32), size_t(511)}) {
    RngHealthCtx ctx;
    rng_health_init(&ctx);
    for (size_t off = 0; off < v.size(); off += chunk) {
      size_t n = std::min(chunk, v.size() - off);
      rng_health_update(&ctx, v.data() + off, n);
    }
    EXPECT_FALSE(rng_health_final(&ctx)) << "chunk size " << chunk;
  }
}

// THE SCOPE FIX, PINNED AS TESTS.
//
// The gate used to live in one function -- reset_init() -- so recovery, import,
// LoadDevice, PIN and wipe-code changes, U2F registration and the OTP block all
// drew key material without it. random_buffer_checked() is the single place
// that consumes the verdict; what matters is that it fails CLOSED rather than
// handing back whatever the source produced.

TEST(RngHealth, CheckedDrawFillsFromAHealthySource) {
  rng_health_force_verdict(true);
  uint8_t a[64] = {0};
  uint8_t b[64] = {0};
  ASSERT_TRUE(random_buffer_checked(a, sizeof(a)));
  ASSERT_TRUE(random_buffer_checked(b, sizeof(b)));
  EXPECT_NE(0, memcmp(a, b, sizeof(a))) << "two draws matched — RNG broken?";
}

// The property the whole change exists for: on a failed verdict the caller gets
// false AND a zeroed buffer, so a caller that ignores the return value still
// cannot walk away with key material from a source that did not pass.
TEST(RngHealth, CheckedDrawFailsClosedAndWipes) {
  rng_health_force_verdict(false);
  uint8_t buf[64];
  memset(buf, 0xAB, sizeof(buf));

  EXPECT_FALSE(random_buffer_checked(buf, sizeof(buf)));

  const uint8_t zeros[64] = {0};
  EXPECT_EQ(0, memcmp(buf, zeros, sizeof(buf)))
      << "buffer kept its contents after a refused draw";
  EXPECT_FALSE(rng_health_check());

  rng_health_force_verdict(true);
}

TEST(RngHealth, CheckedDrawRejectsNull) {
  rng_health_force_verdict(true);
  EXPECT_FALSE(random_buffer_checked(nullptr, 32));
}

// The paths with nowhere to report a failure -- storage_setPin_impl() drawing
// the storage encryption key, for one -- halt instead of continuing.
TEST(RngHealthDeathTest, OrDieHaltsOnAFailedVerdict) {
  EXPECT_EXIT(
      {
        rng_health_force_verdict(false);
        uint8_t buf[64];
        random_buffer_or_die(buf, sizeof(buf));
      },
      ::testing::ExitedWithCode(1), "");
}

}  // namespace
