extern "C" {
#include "keepkey/rand/rng_health.h"
}

#include <gtest/gtest.h>

#include <cstdint>
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
    for (auto &b : v)
      if (b == ref) b = ref ^ 0x01;
    v[0] = ref;  // the reference sample itself counts as 1
    for (uint32_t i = 0; i < extra; i++) v[8 + i * 16] = ref;
    return v;
  };

  auto ok = build(RNG_HEALTH_APT_CUTOFF - 2);  // total = cutoff - 1
  EXPECT_TRUE(rng_health_analyze(ok.data(), ok.size()));

  auto bad = build(RNG_HEALTH_APT_CUTOFF - 1);  // total = cutoff
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

}  // namespace
