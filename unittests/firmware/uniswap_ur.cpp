#include "gtest/gtest.h"

extern "C" {
#include "keepkey/firmware/uniswap_ur.h"
}

#include <string>
#include <vector>

#include "uniswap_ur_vectors.h"

namespace {

std::vector<uint8_t> unhex(const std::string& h) {
  std::vector<uint8_t> out;
  for (size_t i = 0; i + 1 < h.size(); i += 2) {
    out.push_back((uint8_t)std::stoul(h.substr(i, 2), nullptr, 16));
  }
  return out;
}

std::string hex(const uint8_t* p, size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) {
    s += d[p[i] >> 4];
    s += d[p[i] & 15];
  }
  return s;
}

size_t word(const std::vector<uint8_t>& b, size_t off) {
  size_t v = 0;
  for (size_t i = off + 24; i < off + 32; i++) v = (v << 8) | b[i];
  return v;
}

/* Byte index of command i inside execute() calldata. */
size_t command_index(const std::vector<uint8_t>& cd, size_t i) {
  return 4 + word(cd, 4) + 32 + i;
}

/* Start of input i's data (after its length word). */
size_t input_data(const std::vector<uint8_t>& cd, size_t i) {
  size_t heads = 4 + word(cd, 4 + 32) + 32;
  return heads + word(cd, heads + 32 * i) + 32;
}

const std::vector<uint8_t>& sample(int kind) {
  static std::vector<std::vector<uint8_t>> cache(16);
  if (cache[kind].empty()) {
    for (const auto& v : urv::accepted()) {
      for (const auto& st : v.steps) {
        if (st.kind == kind) {
          cache[kind] = unhex(v.calldata);
          return cache[kind];
        }
      }
    }
  }
  return cache[kind];
}

}  // namespace

TEST(UniswapUr, RealBaseSwapsDecodeAsTheIndependentDecoderSays) {
  ASSERT_GE(urv::accepted().size(), 40u);
  for (const auto& v : urv::accepted()) {
    std::vector<uint8_t> cd = unhex(v.calldata);
    UrPlan plan;
    ASSERT_TRUE(ur_decode(cd.data(), cd.size(), &plan)) << v.tx;
    ASSERT_EQ(plan.n, v.steps.size()) << v.tx;
    for (size_t i = 0; i < plan.n; i++) {
      const UrStep& got = plan.steps[i];
      const urv::Step& want = v.steps[i];
      EXPECT_EQ((int)got.kind, want.kind) << v.tx << " step " << i;
      if (!want.token_in.empty()) {
        EXPECT_EQ(hex(got.token_in, 20), want.token_in) << v.tx;
      }
      if (!want.token_out.empty()) {
        EXPECT_EQ(hex(got.token_out, 20), want.token_out) << v.tx;
      }
      EXPECT_EQ(hex(got.amount, 32), want.amount) << v.tx << " step " << i;
      if (!want.limit.empty()) {
        EXPECT_EQ(hex(got.limit, 32), want.limit) << v.tx << " step " << i;
      }
    }
  }
}

TEST(UniswapUr, V4SwapsAreNotDecoded) {
  ASSERT_FALSE(urv::v4_rejected().empty());
  for (const auto& h : urv::v4_rejected()) {
    std::vector<uint8_t> cd = unhex(h);
    UrPlan plan;
    EXPECT_FALSE(ur_decode(cd.data(), cd.size(), &plan));
    EXPECT_EQ(plan.n, 0);  // never a partial plan
  }
}

TEST(UniswapUr, AllowRevertFlagIsNotDecoded) {
  std::vector<uint8_t> cd = sample(UR_V3_SWAP_EXACT_IN);
  ASSERT_FALSE(cd.empty());
  UrPlan plan;
  ASSERT_TRUE(ur_decode(cd.data(), cd.size(), &plan));
  cd[command_index(cd, 0)] |= 0x80;
  EXPECT_FALSE(ur_decode(cd.data(), cd.size(), &plan));
}

TEST(UniswapUr, UnknownCommandIsNotDecoded) {
  std::vector<uint8_t> cd = sample(UR_V3_SWAP_EXACT_IN);
  cd[command_index(cd, 0)] = 0x10;  // V4_SWAP
  UrPlan plan;
  EXPECT_FALSE(ur_decode(cd.data(), cd.size(), &plan));
}

TEST(UniswapUr, TruncatedCalldataIsNotDecoded) {
  std::vector<uint8_t> cd = sample(UR_V3_SWAP_EXACT_IN);
  UrPlan plan;
  for (size_t cut = 1; cut < cd.size(); cut += 31) {
    EXPECT_FALSE(ur_decode(cd.data(), cd.size() - cut, &plan)) << cut;
  }
}

TEST(UniswapUr, DirtyRecipientWordIsNotDecoded) {
  std::vector<uint8_t> cd = sample(UR_V3_SWAP_EXACT_IN);
  size_t step = 0;
  UrPlan plan;
  ASSERT_TRUE(ur_decode(cd.data(), cd.size(), &plan));
  while (plan.steps[step].kind != UR_V3_SWAP_EXACT_IN) step++;
  cd[input_data(cd, step)] = 0x01;  // high byte of the recipient word
  EXPECT_FALSE(ur_decode(cd.data(), cd.size(), &plan));
}

TEST(UniswapUr, Permit2AmountWiderThanUint160IsNotDecoded) {
  std::vector<uint8_t> cd = sample(UR_PERMIT2_PERMIT);
  ASSERT_FALSE(cd.empty());
  UrPlan plan;
  ASSERT_TRUE(ur_decode(cd.data(), cd.size(), &plan));
  size_t step = 0;
  while (plan.steps[step].kind != UR_PERMIT2_PERMIT) step++;
  cd[input_data(cd, step) + 32] = 0x01;  // amount word, above 160 bits
  EXPECT_FALSE(ur_decode(cd.data(), cd.size(), &plan));
}

TEST(UniswapUr, CommandAndInputCountsMustAgree) {
  std::vector<uint8_t> cd = sample(UR_PERMIT2_PERMIT);
  // Shorten the commands string by one: inputs now outnumber commands.
  size_t len_word = 4 + word(cd, 4);
  cd[len_word + 31] -= 1;
  UrPlan plan;
  EXPECT_FALSE(ur_decode(cd.data(), cd.size(), &plan));
}

TEST(UniswapUr, RecipientConstants) {
  uint8_t r[20] = {0};
  r[19] = UR_RECIPIENT_MSG_SENDER;
  EXPECT_TRUE(ur_recipient_is_constant(r, UR_RECIPIENT_MSG_SENDER));
  EXPECT_FALSE(ur_recipient_is_constant(r, UR_RECIPIENT_ADDRESS_THIS));
  r[0] = 1;
  EXPECT_FALSE(ur_recipient_is_constant(r, UR_RECIPIENT_MSG_SENDER));
}

namespace {
bool summarize_vec(const urv::Vec& v, UrSummary* s, UrPlan* plan) {
  std::vector<uint8_t> cd = unhex(v.calldata);
  std::vector<uint8_t> router = unhex(v.router);
  std::vector<uint8_t> value = unhex(v.value);
  return ur_decode(cd.data(), cd.size(), plan) &&
         ur_summarize(plan, router.data(), value.data(), s);
}
bool has_kind(const urv::Vec& v, int kind) {
  for (const auto& st : v.steps)
    if (st.kind == kind) return true;
  return false;
}
}  // namespace

/* Every swap shaped like the Uniswap app's (permit or wrap, one swap, the
 * user pays) must summarize, with amounts read from the swap step. */
TEST(UniswapUr, AppShapedSwapsSummarize) {
  size_t permit_swaps = 0, wrap_swaps = 0;
  for (const auto& v : urv::accepted()) {
    UrPlan plan;
    UrSummary s;
    const bool permit = has_kind(v, UR_PERMIT2_PERMIT);
    const bool wrap = has_kind(v, UR_WRAP_ETH);
    if (!permit && !wrap) continue;
    ASSERT_TRUE(summarize_vec(v, &s, &plan)) << v.tx;
    const urv::Step* swap = nullptr;
    for (const auto& st : v.steps)
      if (st.kind == UR_V3_SWAP_EXACT_IN || st.kind == UR_V3_SWAP_EXACT_OUT)
        swap = &st;
    ASSERT_NE(swap, nullptr);
    EXPECT_EQ(hex(s.token_in, 20), swap->token_in) << v.tx;
    EXPECT_EQ(hex(s.token_out, 20), swap->token_out) << v.tx;
    EXPECT_EQ(s.has_permit, permit) << v.tx;
    EXPECT_EQ(s.in_is_eth, wrap) << v.tx;
    if (wrap) {
      EXPECT_EQ(hex(s.amount_in, 32), v.value) << v.tx;  // spends msg.value
      wrap_swaps++;
    } else if (s.exact_in) {
      EXPECT_EQ(hex(s.amount_in, 32), swap->amount) << v.tx;
      EXPECT_EQ(hex(s.amount_out, 32), swap->limit) << v.tx;
    }
    if (permit) permit_swaps++;
  }
  EXPECT_GE(permit_swaps, 30u);
  EXPECT_GE(wrap_swaps, 1u);  // the case is covered; counts vary by sample
}

const urv::Vec* first_with(int kind) {
  for (const auto& v : urv::accepted())
    if (has_kind(v, kind)) return &v;
  return nullptr;
}

TEST(UniswapUr, PermitForAnotherSpenderDoesNotSummarize) {
  const urv::Vec* v = first_with(UR_PERMIT2_PERMIT);
  ASSERT_NE(v, nullptr);
  UrPlan plan;
  UrSummary s;
  ASSERT_TRUE(summarize_vec(*v, &s, &plan));  // control
  std::vector<uint8_t> other = unhex(v->router);
  other[19] ^= 1;
  std::vector<uint8_t> value = unhex(v->value);
  EXPECT_FALSE(ur_summarize(&plan, other.data(), value.data(), &s));
}

TEST(UniswapUr, EthWithoutWrapDoesNotSummarize) {
  const urv::Vec* v = first_with(UR_PERMIT2_PERMIT);
  UrPlan plan;
  UrSummary s;
  ASSERT_TRUE(summarize_vec(*v, &s, &plan));
  std::vector<uint8_t> router = unhex(v->router);
  uint8_t value[32] = {0};
  value[31] = 1;  // 1 wei the screens would never mention
  EXPECT_FALSE(ur_summarize(&plan, router.data(), value, &s));
}

TEST(UniswapUr, ExtraStepDoesNotSummarize) {
  const urv::Vec* v = first_with(UR_PERMIT2_PERMIT);
  UrPlan plan;
  UrSummary s;
  ASSERT_TRUE(summarize_vec(*v, &s, &plan));
  std::vector<uint8_t> router = unhex(v->router);
  std::vector<uint8_t> value = unhex(v->value);
  ASSERT_LT(plan.n, UR_MAX_STEPS);
  plan.steps[plan.n] = plan.steps[plan.n - 1];  // a second swap
  plan.n++;
  EXPECT_FALSE(ur_summarize(&plan, router.data(), value.data(), &s));
}

/* size_t is 32-bit on the device: an offset above 2^32 must be refused, not
 * wrapped to a small one the router never reads. */
TEST(UniswapUr, OffsetsWiderThan32BitsAreNotDecoded) {
  std::vector<uint8_t> cd = sample(UR_V3_SWAP_EXACT_IN);
  UrPlan plan;
  ASSERT_TRUE(ur_decode(cd.data(), cd.size(), &plan));
  cd[4 + 27] = 0x01;  // commands offset word: 2^32 + original
  EXPECT_FALSE(ur_decode(cd.data(), cd.size(), &plan));
}
