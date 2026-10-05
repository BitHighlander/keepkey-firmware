#include "gtest/gtest.h"

extern "C" {
#include "keepkey/firmware/uniswap_ur.h"
}

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "uniswap_ur_oracle.h"
#include "uniswap_ur_sample.h"
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

/* ---- Streaming decoder vs the buffered decoder it replaced (D-021) ----
 * uniswap_ur_oracle.c is the 162bc884f ur_decode(), kept as a test oracle.
 * Every real call, cut into chunks the way SignTx delivers them (a first
 * chunk of up to 1,024 B, then data chunks of any size), must give the same
 * plan, byte for byte, or the same refusal. */
namespace {

struct Outcome {
  bool ok;
  UrPlan plan;
};

Outcome stream_decode(const std::vector<uint8_t>& cd,
                      const std::vector<size_t>& chunks) {
  Outcome o;
  memset(&o.plan, 0xa5, sizeof(o.plan));  // begin must clear it
  UrStream s;
  ur_stream_begin(&s, &o.plan, cd.size());
  size_t off = 0;
  for (size_t c : chunks) {
    c = std::min(c, cd.size() - off);
    if (c == 0) break;
    ur_stream_feed(&s, cd.data() + off, c);  // refusals latch; keep feeding
    off += c;
  }
  o.ok = ur_stream_finish(&s);
  return o;
}

uint32_t xorshift(uint32_t* x) {
  *x ^= *x << 13;
  *x ^= *x >> 17;
  *x ^= *x << 5;
  return *x;
}

/* Single shot; 1024 + 64s; 1024 + 1s; 1024 + random; random first chunk
 * (<= 1024) + random; every byte alone. Seeded: the same cuts every run. */
std::vector<std::vector<size_t>> chunkings(size_t len, uint32_t seed) {
  std::vector<std::vector<size_t>> out;
  out.push_back({len});
  const size_t first = std::min<size_t>(len, 1024);
  std::vector<size_t> c64{first}, c1{first}, crand{first};
  for (size_t at = first; at < len; at += 64) c64.push_back(64);
  for (size_t at = first; at < len; at++) c1.push_back(1);
  uint32_t x = seed * 2654435761u + 1;
  for (size_t at = first; at < len;) {
    size_t c = 1 + xorshift(&x) % 300;
    crand.push_back(c);
    at += c;
  }
  std::vector<size_t> rfirst{1 + xorshift(&x) % first};
  for (size_t at = rfirst[0]; at < len;) {
    size_t c = 1 + xorshift(&x) % 97;
    rfirst.push_back(c);
    at += c;
  }
  out.push_back(c64);
  out.push_back(c1);
  out.push_back(crand);
  out.push_back(rfirst);
  out.push_back(std::vector<size_t>(len, 1));
  return out;
}

/* Number of chunkings whose result differs from the oracle's. */
size_t differs_from_oracle(const std::vector<uint8_t>& cd, uint32_t seed,
                           bool* oracle_ok) {
  UrPlan want, zero;
  memset(&zero, 0, sizeof(zero));
  *oracle_ok = ur_oracle_decode(cd.data(), cd.size(), &want);
  size_t bad = 0;
  for (const auto& ch : chunkings(cd.size(), seed)) {
    Outcome got = stream_decode(cd, ch);
    if (got.ok != *oracle_ok) {
      bad++;
    } else if (*oracle_ok) {
      bad += memcmp(&got.plan, &want, sizeof(want)) != 0;
    } else {
      /* The oracle can leave has_deadline/deadline behind on a refusal; the
       * stream always clears the plan. Nothing reads a refused plan. */
      bad += want.n != 0 || memcmp(&got.plan, &zero, sizeof(zero)) != 0;
    }
  }
  return bad;
}

size_t command_count(const std::vector<uint8_t>& cd) {
  return cd.size() < 4 + 64 ? 0 : word(cd, 4 + word(cd, 4));
}

}  // namespace

TEST(UniswapUrStream, MatchesTheBufferedDecoderOnEveryVector) {
  size_t calls = 0, decoded = 0;
  uint32_t seed = 1;
  for (const auto& v : urv::accepted()) {
    bool ok;
    EXPECT_EQ(differs_from_oracle(unhex(v.calldata), seed++, &ok), 0u) << v.tx;
    EXPECT_TRUE(ok) << v.tx;
    calls++;
    decoded += ok;
  }
  for (const auto& h : urv::v4_rejected()) {
    bool ok;
    EXPECT_EQ(differs_from_oracle(unhex(h), seed++, &ok), 0u);
    EXPECT_FALSE(ok);
    calls++;
  }
  printf("vectors: %zu calls x 6 chunkings, %zu decoded, all identical\n",
         calls, decoded);
  EXPECT_EQ(calls, urv::accepted().size() + urv::v4_rejected().size());
}

/* The D-021 sample: 1,000 consecutive calls to the app's Base router. */
TEST(UniswapUrStream, MatchesTheBufferedDecoderOnTheD021Sample) {
  const auto& calls = urs::calls();
  ASSERT_EQ(calls.size(), 1000u) << "missing " UR_SAMPLE_PATH;
  size_t decoded = 0, mismatched = 0, long_decoded = 0;
  uint32_t seed = 1000;
  for (const auto& c : calls) {
    bool ok;
    const size_t bad = differs_from_oracle(c.calldata, seed++, &ok);
    EXPECT_EQ(bad, 0u) << c.tx;
    mismatched += bad != 0;
    decoded += ok;
    long_decoded += ok && c.calldata.size() > 1472;
  }
  printf("sample: %zu calls x 6 chunkings, %zu decoded (%zu over 1,472 B), "
         "%zu mismatched\n",
         calls.size(), decoded, long_decoded, mismatched);
  EXPECT_EQ(mismatched, 0u);
  /* D-021's count of calls whose commands are all in the V2/V3 subset is
   * 740 (one sets an allow-revert flag, which is refused). */
  EXPECT_GE(decoded, 739u);
  /* The 1,472-byte buffer refused these; streaming decodes them. */
  EXPECT_GT(long_decoded, 0u);
}

/* Long calls that decode are not just accepted: their summary is what the
 * buffered decoder would have shown with an unlimited buffer. */
TEST(UniswapUrStream, CallsPastTheOldBufferDecodeInChunks) {
  size_t n = 0;
  for (const auto& c : urs::calls()) {
    if (c.calldata.size() <= 1472) continue;
    UrPlan want;
    if (!ur_oracle_decode(c.calldata.data(), c.calldata.size(), &want))
      continue;
    std::vector<size_t> ch{1024};
    for (size_t at = 1024; at < c.calldata.size(); at += 128) ch.push_back(128);
    Outcome got = stream_decode(c.calldata, ch);
    ASSERT_TRUE(got.ok) << c.tx;
    EXPECT_EQ(0, memcmp(&got.plan, &want, sizeof(want))) << c.tx;
    EXPECT_GE(got.plan.n, 1u);
    n++;
  }
  printf("calls over 1,472 B decoded: %zu\n", n);
  EXPECT_GT(n, 0u);
}

/* Never looser: whatever the stream accepts, the buffered decoder accepts
 * with the same plan. Random byte changes to real calls; the stream may
 * refuse more (an offset pointing backwards), never less. */
TEST(UniswapUrStream, NeverAcceptsWhatTheBufferedDecoderRefuses) {
  uint32_t x = 0x7730u;
  size_t tried = 0, both = 0, stricter = 0;
  for (const auto& v : urv::accepted()) {
    const std::vector<uint8_t> cd = unhex(v.calldata);
    for (int m = 0; m < 40; m++) {
      std::vector<uint8_t> t = cd;
      /* Mostly the low bytes of words (offsets, lengths, counts). */
      const int edits = 1 + xorshift(&x) % 3;
      for (int e = 0; e < edits; e++) {
        size_t at = 4 + 32 * (xorshift(&x) % ((t.size() - 4) / 32)) + 31;
        if (xorshift(&x) % 4 == 0) at = xorshift(&x) % t.size();
        t[at] = (uint8_t)(xorshift(&x) % 4 == 0 ? xorshift(&x)
                                                 : t[at] + 32 * (int)(xorshift(&x) % 5) - 64);
      }
      UrPlan want;
      const bool oracle = ur_oracle_decode(t.data(), t.size(), &want);
      Outcome got = stream_decode(t, chunkings(t.size(), m)[3]);
      tried++;
      if (got.ok) {
        ASSERT_TRUE(oracle) << v.tx << " mutation " << m;
        ASSERT_EQ(0, memcmp(&got.plan, &want, sizeof(want))) << v.tx;
        both++;
      } else if (oracle) {
        stricter++;
      }
    }
  }
  printf("mutations: %zu tried, %zu accepted by both, %zu refused only by "
         "the stream\n", tried, both, stricter);
}

namespace {
void put_word(std::vector<uint8_t>* b, size_t off, size_t v) {
  for (int i = 31; i >= 0; i--, v >>= 8) (*b)[off + i] = (uint8_t)(i >= 24 ? v : 0);
}

/* The same call with its bytes[] elements laid out in reverse order, heads
 * pointing at them: valid for abi.decode, refused by a forward-only reader. */
std::vector<uint8_t> reverse_inputs(const std::vector<uint8_t>& cd) {
  const size_t arr = 4 + word(cd, 4 + 32);
  const size_t n = word(cd, arr), heads = arr + 32;
  std::vector<std::vector<uint8_t>> el;
  size_t end = heads + 32 * n;
  for (size_t i = 0; i < n; i++) {
    const size_t off = heads + word(cd, heads + 32 * i);
    const size_t size = 32 + (word(cd, off) + 31) / 32 * 32;
    el.emplace_back(cd.begin() + off, cd.begin() + off + size);
    end = std::max(end, off + size);
  }
  std::vector<uint8_t> out(cd.begin(), cd.begin() + heads + 32 * n);
  size_t rel = 32 * n;
  for (size_t i = n; i-- > 0;) {
    put_word(&out, heads + 32 * i, rel);
    out.insert(out.end(), el[i].begin(), el[i].end());
    rel += el[i].size();
  }
  out.insert(out.end(), cd.begin() + end, cd.end());
  return out;
}
}  // namespace

TEST(UniswapUrStream, InputsOutOfOrderAreRefused) {
  const urv::Vec* v = first_with(UR_PERMIT2_PERMIT);
  ASSERT_NE(v, nullptr);
  std::vector<uint8_t> cd = reverse_inputs(unhex(v->calldata));
  UrPlan plan;
  ASSERT_TRUE(ur_oracle_decode(cd.data(), cd.size(), &plan));  // abi-valid
  EXPECT_FALSE(ur_decode(cd.data(), cd.size(), &plan));
  EXPECT_EQ(plan.n, 0);
  // The layout as sent decodes.
  std::vector<uint8_t> same = unhex(v->calldata);
  EXPECT_TRUE(ur_decode(same.data(), same.size(), &plan));
}

TEST(UniswapUrStream, OffsetIntoTheCommandsIsRefused) {
  // The inputs array offset pointing back at the commands' length word: the
  // stream has read past it.
  std::vector<uint8_t> cd = sample(UR_V3_SWAP_EXACT_IN);
  put_word(&cd, 4 + 32, word(cd, 4));
  UrPlan plan;
  EXPECT_FALSE(ur_decode(cd.data(), cd.size(), &plan));
}

TEST(UniswapUrStream, MoreBytesThanDeclaredAreRefused) {
  std::vector<uint8_t> cd = sample(UR_V3_SWAP_EXACT_IN);
  UrPlan plan;
  UrStream s;
  ur_stream_begin(&s, &plan, cd.size() - 1);
  EXPECT_FALSE(ur_stream_feed(&s, cd.data(), cd.size()));
  EXPECT_FALSE(ur_stream_finish(&s));
  EXPECT_EQ(plan.n, 0);
  // A refusal is final: the right bytes afterwards do not revive it.
  ur_stream_begin(&s, &plan, cd.size());
  std::vector<uint8_t> bad = cd;
  bad[0] ^= 1;  // selector
  EXPECT_FALSE(ur_stream_feed(&s, bad.data(), 4));
  EXPECT_FALSE(ur_stream_feed(&s, cd.data() + 4, cd.size() - 4));
  EXPECT_FALSE(ur_stream_finish(&s));
}

TEST(UniswapUrStream, ShortCallIsRefusedAtFinish) {
  std::vector<uint8_t> cd = sample(UR_V3_SWAP_EXACT_IN);
  UrPlan plan;
  UrStream s;
  ur_stream_begin(&s, &plan, cd.size());
  EXPECT_TRUE(ur_stream_feed(&s, cd.data(), cd.size() - 1));
  EXPECT_FALSE(ur_stream_finish(&s));
  EXPECT_EQ(plan.n, 0);
}
