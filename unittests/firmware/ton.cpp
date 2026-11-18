extern "C" {
#include "keepkey/firmware/ton.h"
}
#include "gtest/gtest.h"
#include <cstring>
#include <cstdio>

namespace {
struct TonVector {
  const char* address;
  uint64_t amount;
  uint32_t seqno;
  uint32_t expiry;
  bool bounce;
  const char* memo;
  int32_t workchain;
  const char* hash;
};
/* Generated independently with pinned @ton/core 0.63.1. */
#include "ton_vectors.h"

TonSignTx request(const TonVector& v) {
  TonSignTx m = TonSignTx_init_default;
  m.has_raw_tx = m.has_to_address = m.has_amount = m.has_seqno = true;
  m.has_expire_at = m.has_bounce = m.has_memo = m.has_workchain = true;
  m.raw_tx.size = 32;
  for (size_t i = 0; i < 32; i++) {
    unsigned byte = 0;
    sscanf(v.hash + 2 * i, "%2x", &byte);
    m.raw_tx.bytes[i] = byte;
  }
  strcpy(m.to_address, v.address);
  strcpy(m.memo, v.memo);
  m.amount = v.amount;
  m.seqno = v.seqno;
  m.expire_at = v.expiry;
  m.bounce = v.bounce;
  m.workchain = v.workchain;
  return m;
}

TEST(TonTransfer, MatchesIndependentCellHashesAtInlineAndReferenceBoundaries) {
  for (const auto& v : TON_VECTORS) {
    auto m = request(v);
    char recipient[70] = {0};
    EXPECT_TRUE(ton_verify_transfer(&m, recipient)) << v.hash;
    EXPECT_EQ(v.workchain == -1 ? "-1:" : "0:",
              std::string(recipient).substr(0, v.workchain == -1 ? 3 : 2));
  }
}

TEST(TonTransfer, RejectsEveryUnboundDisplayFieldAndIncompleteClaims) {
  for (const auto& v : TON_VECTORS) {
    const auto original = request(v);
    char recipient[70];
    auto m = original;
    m.amount ^= 1;
    EXPECT_FALSE(ton_verify_transfer(&m, recipient));
    m = original;
    m.seqno ^= 1;
    EXPECT_FALSE(ton_verify_transfer(&m, recipient));
    m = original;
    m.expire_at ^= 1;
    EXPECT_FALSE(ton_verify_transfer(&m, recipient));
    m = original;
    m.bounce = !m.bounce;
    EXPECT_FALSE(ton_verify_transfer(&m, recipient));
    m = original;
    m.workchain = m.workchain == 0 ? -1 : 0;
    EXPECT_FALSE(ton_verify_transfer(&m, recipient));
    m = original;
    m.memo[0] = m.memo[0] == 'A' ? 'B' : 'A';
    EXPECT_FALSE(ton_verify_transfer(&m, recipient));
    m = original;
    m.raw_tx.bytes[31] ^= 1;
    EXPECT_FALSE(ton_verify_transfer(&m, recipient));
    m = original;
    m.to_address[47] = m.to_address[47] == 'A' ? 'B' : 'A';
    EXPECT_FALSE(ton_verify_transfer(&m, recipient));
    m = original;
    m.has_amount = false;
    EXPECT_FALSE(ton_verify_transfer(&m, recipient));
  }
}
}  // namespace
