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

/* Sum of two equal-width big-endian hex strings (test-side, independent of
 * the decoder's add32). */
std::string hex_add(const std::string& x, const std::string& y) {
  std::vector<uint8_t> a = unhex(x), b = unhex(y), r(a.size());
  unsigned carry = 0;
  for (size_t i = a.size(); i-- > 0;) {
    carry += (unsigned)a[i] + b[i];
    r[i] = (uint8_t)carry;
    carry >>= 8;
  }
  return hex(r.data(), r.size());
}

bool is_exact_in(int kind) {
  return kind == UR_V3_SWAP_EXACT_IN || kind == UR_V2_SWAP_EXACT_IN;
}

/* Every app-shaped call (permit or wrap first) with one swap, or a split of
 * two exact-in swaps of the same pair, summarizes: totals from the swaps,
 * and the floor raised to a later unwrap/sweep minimum when there is no fee.
 * A second swap of a different pair (a multi-hop through two pool versions)
 * is refused. */
TEST(UniswapUr, AppShapedSwapsSummarize) {
  size_t permit_swaps = 0, wrap_swaps = 0, splits = 0, cleanups = 0;
  for (const auto& v : urv::accepted()) {
    UrPlan plan;
    UrSummary s;
    const bool permit = has_kind(v, UR_PERMIT2_PERMIT);
    const bool wrap = has_kind(v, UR_WRAP_ETH);
    if (!permit && !wrap) continue;
    std::vector<const urv::Step*> swaps;
    for (const auto& st : v.steps)
      if (st.kind <= UR_V2_SWAP_EXACT_OUT) swaps.push_back(&st);
    const bool same_pair =
        swaps.size() == 2 && is_exact_in(swaps[0]->kind) &&
        is_exact_in(swaps[1]->kind) &&
        swaps[0]->token_in == swaps[1]->token_in &&
        swaps[0]->token_out == swaps[1]->token_out;
    if (swaps.size() > 2 || (swaps.size() == 2 && !same_pair)) {
      EXPECT_FALSE(summarize_vec(v, &s, &plan)) << v.tx;
      continue;
    }
    ASSERT_TRUE(summarize_vec(v, &s, &plan)) << v.tx;
    const urv::Step* swap = swaps[0];
    std::string amount = swap->amount, limit = swap->limit;
    if (swaps.size() == 2) {
      amount = hex_add(amount, swaps[1]->amount);
      limit = hex_add(limit, swaps[1]->limit);
      splits++;
    }
    EXPECT_EQ(hex(s.token_in, 20), swap->token_in) << v.tx;
    EXPECT_EQ(hex(s.token_out, 20), swap->token_out) << v.tx;
    EXPECT_EQ(s.has_permit, permit) << v.tx;
    EXPECT_EQ(s.in_is_eth, wrap) << v.tx;
    size_t tail = 0;
    std::string floor = limit;
    for (const auto& st : v.steps) {
      if (st.kind != UR_UNWRAP_WETH && st.kind != UR_SWEEP) continue;
      tail++;
      if (!has_kind(v, UR_PAY_PORTION) && st.amount > floor) floor = st.amount;
    }
    if (tail == 2 || (tail == 1 && !s.out_is_eth && has_kind(v, UR_UNWRAP_WETH)))
      cleanups++;
    if (wrap) {
      EXPECT_EQ(hex(s.amount_in, 32), v.value) << v.tx;  // spends msg.value
      wrap_swaps++;
    } else if (s.exact_in) {
      EXPECT_EQ(hex(s.amount_in, 32), amount) << v.tx;
      EXPECT_EQ(hex(s.amount_out, 32), floor) << v.tx;
    }
    if (permit) permit_swaps++;
  }
  EXPECT_GE(permit_swaps, 30u);
  EXPECT_GE(wrap_swaps, 1u);  // the case is covered; counts vary by sample
  EXPECT_GE(splits, 1u);
  EXPECT_GE(cleanups, 1u);
}

/* The clean-up step returns ETH only to the recipient the review names. */
TEST(UniswapUr, CleanupGoesOnlyToTheShownRecipient) {
  const urv::Vec* v = nullptr;
  for (const auto& c : urv::accepted())
    if (c.steps.size() >= 3 && c.steps.back().kind == UR_SWEEP &&
        (has_kind(c, UR_PERMIT2_PERMIT) || has_kind(c, UR_WRAP_ETH)))
      v = &c;
  ASSERT_NE(v, nullptr);
  UrPlan plan;
  UrSummary s;
  ASSERT_TRUE(summarize_vec(*v, &s, &plan)) << v->tx;
  std::vector<uint8_t> router = unhex(v->router);
  std::vector<uint8_t> value = unhex(v->value);
  UrPlan other = plan;
  other.steps[other.n - 1].recipient[0] ^= 1;
  EXPECT_FALSE(ur_summarize(&other, router.data(), value.data(), &s));
  other = plan;
  other.steps[other.n - 1].token_in[19] ^= 1;  // sweeping a token, not ETH
  EXPECT_FALSE(ur_summarize(&other, router.data(), value.data(), &s));
}

/* A split's second swap must match the first: same pair, same recipient. */
TEST(UniswapUr, SplitRouteMustBeTheSamePair) {
  const urv::Vec* v = nullptr;
  UrPlan plan;
  UrSummary s;
  for (const auto& c : urv::accepted()) {
    size_t n = 0;
    for (const auto& st : c.steps) n += st.kind <= UR_V2_SWAP_EXACT_OUT;
    if (n == 2 && summarize_vec(c, &s, &plan)) {
      v = &c;
      break;
    }
  }
  ASSERT_NE(v, nullptr) << "no same-pair split in the vectors";
  std::vector<uint8_t> router = unhex(v->router);
  std::vector<uint8_t> value = unhex(v->value);
  size_t second = 0;
  for (size_t k = 0; k < plan.n; k++)
    if (plan.steps[k].kind <= UR_V2_SWAP_EXACT_OUT) second = k;
  UrPlan other = plan;
  other.steps[second].token_out[19] ^= 1;
  EXPECT_FALSE(ur_summarize(&other, router.data(), value.data(), &s));
  other = plan;
  other.steps[second].recipient[0] ^= 1;
  EXPECT_FALSE(ur_summarize(&other, router.data(), value.data(), &s));
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

/* Exact-out ETH in refunds the unspent ETH: only to the swap's recipient,
 * and the swap may not be allowed to spend more than was sent. */
TEST(UniswapUr, ExactOutEthRefundsOnlyToTheRecipient) {
  const urv::Vec* v = nullptr;
  for (const auto& c : urv::accepted())
    if (c.steps.size() == 3 && c.steps[0].kind == UR_WRAP_ETH &&
        (c.steps[1].kind == UR_V3_SWAP_EXACT_OUT ||
         c.steps[1].kind == UR_V2_SWAP_EXACT_OUT) &&
        c.steps[2].kind == UR_UNWRAP_WETH)
      v = &c;
  ASSERT_NE(v, nullptr);
  UrPlan plan;
  UrSummary s;
  ASSERT_TRUE(summarize_vec(*v, &s, &plan)) << v->tx;
  EXPECT_TRUE(s.in_is_eth);
  EXPECT_FALSE(s.exact_in);
  EXPECT_EQ(hex(s.amount_in, 32), v->value);  // at most what was sent
  std::vector<uint8_t> router = unhex(v->router);
  std::vector<uint8_t> value = unhex(v->value);

  UrPlan other = plan;
  other.steps[2].recipient[0] ^= 1;  // refund elsewhere
  EXPECT_FALSE(ur_summarize(&other, router.data(), value.data(), &s));

  other = plan;
  memset(other.steps[1].limit, 0xff, 32);  // may spend more than was sent
  EXPECT_FALSE(ur_summarize(&other, router.data(), value.data(), &s));
}

TEST(UniswapUr, ExtraStepDoesNotSummarize) {
  const urv::Vec* v = first_with(UR_PERMIT2_PERMIT);
  UrPlan plan;
  UrSummary s;
  ASSERT_TRUE(summarize_vec(*v, &s, &plan));
  std::vector<uint8_t> router = unhex(v->router);
  std::vector<uint8_t> value = unhex(v->value);
  ASSERT_LT(plan.n, UR_MAX_STEPS);
  plan.steps[plan.n] = plan.steps[plan.n - 1];
  plan.steps[plan.n].kind = UR_TRANSFER;  // a step no reviewed shape has
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
