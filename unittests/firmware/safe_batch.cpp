#include <gtest/gtest.h>

#include <algorithm>
#include <vector>

extern "C" {
#include "keepkey/firmware/safe_batch.h"
}

namespace {
std::vector<uint8_t> batch(unsigned count = 2) {
  std::vector<uint8_t> out(68);
  out[0] = 0x8d;
  out[1] = 0x80;
  out[2] = 0xff;
  out[3] = 0x0a;
  out[35] = 32;
  for (unsigned i = 0; i < count; i++) {
    out.push_back(0);
    out.insert(out.end(), 20, static_cast<uint8_t>(i + 1));
    out.insert(out.end(), 31, 0);
    out.push_back(i + 1);
    out.insert(out.end(), 31, 0);
    out.push_back(4);
    out.insert(out.end(), {0xaa, 0xbb, 0xcc, static_cast<uint8_t>(i)});
  }
  const uint32_t size = out.size() - 68;
  for (unsigned i = 0; i < 4; i++) out[67 - i] = size >> (i * 8);
  while ((out.size() - 68) % 32) out.push_back(0);
  return out;
}

bool accepts(const std::vector<uint8_t>& data, size_t chunk,
             uint16_t wanted = 0) {
  SafeBatch b{};
  if (!safe_batch_begin(&b, data.size(), wanted)) return false;
  for (size_t i = 0; i < data.size(); i += chunk) {
    if (!safe_batch_feed(&b, data.data() + i, std::min(chunk, data.size() - i)))
      return false;
  }
  return safe_batch_finish(&b);
}
}  // namespace

TEST(SafeBatch, LocatesEachCallAcrossEveryChunkBoundary) {
  const auto bytes = batch();
  for (size_t size : {1, 2, 3, 31, 32, 33, 67, 68, 85, 128, 1024}) {
    ASSERT_TRUE(accepts(bytes, size, 0));
    ASSERT_TRUE(accepts(bytes, size, 1));
    EXPECT_FALSE(accepts(bytes, size, 2));
  }
  SafeBatch b{};
  ASSERT_TRUE(safe_batch_begin(&b, bytes.size(), 1));
  ASSERT_TRUE(safe_batch_feed(&b, bytes.data(), bytes.size()));
  ASSERT_TRUE(safe_batch_finish(&b));
  EXPECT_EQ(b.count, 2);
  EXPECT_EQ(b.offset, 68u + 89u + 85u);
  EXPECT_EQ(b.length, 4u);
  EXPECT_EQ(b.to[0], 2);
  EXPECT_EQ(b.value[31], 2);
  EXPECT_EQ(b.prefix[3], 1);
}

TEST(SafeBatch, RefusesDelegatecallsEvenAfterTheSelectedCall) {
  for (size_t position : {68u, 68u + 89u}) {
    auto bytes = batch();
    bytes[position] = 1;
    EXPECT_FALSE(accepts(bytes, 1));
  }
}

TEST(SafeBatch, HeaderBoundsCannotWrapAtUint32Limit) {
  SafeBatch b{};
  ASSERT_TRUE(safe_batch_begin(&b, UINT32_MAX, 0));
  // Equivalent parser position after streaming a large preceding payload.
  b.received = b.next = UINT32_MAX - 40u;
  b.packed_end = UINT32_MAX;
  const uint8_t call = 0;
  EXPECT_FALSE(safe_batch_feed(&b, &call, 1));
  EXPECT_FALSE(safe_batch_finish(&b));
}

TEST(SafeBatch, RefusesTruncationTrailingBytesDirtyPaddingAndHugeLengths) {
  const auto original = batch();
  for (size_t size = 0; size < original.size(); size++) {
    std::vector<uint8_t> truncated(original.begin(), original.begin() + size);
    EXPECT_FALSE(accepts(truncated, 7));
  }
  for (size_t at :
       std::vector<size_t>{0, 4, 35, 36, 67, 68 + 53, original.size() - 1}) {
    auto bad = original;
    bad[at] ^= 1;
    EXPECT_FALSE(accepts(bad, 7));
  }
  auto trailing = original;
  trailing.insert(trailing.end(), 32, 0);
  EXPECT_FALSE(accepts(trailing, 7));
  EXPECT_FALSE(accepts(batch(0), 1));
  EXPECT_TRUE(accepts(batch(SAFE_BATCH_MAX_CALLS), 1024));
  EXPECT_FALSE(accepts(batch(SAFE_BATCH_MAX_CALLS + 1), 1024));
}
