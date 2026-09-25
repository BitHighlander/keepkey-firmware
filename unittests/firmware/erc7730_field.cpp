extern "C" {
#include "keepkey/firmware/erc7730_capabilities.h"
#include "keepkey/firmware/erc7730_field.h"
#include "keepkey/firmware/erc7730_workflow.h"
}

#include "gtest/gtest.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> hex(const char* text) {
  std::vector<uint8_t> out;
  for (size_t i = 0; text[i] && text[i + 1]; i += 2) {
    unsigned value = 0;
    sscanf(text + i, "%2x", &value);
    out.push_back((uint8_t)value);
  }
  return out;
}

std::vector<uint8_t> word(uint64_t value) {
  std::vector<uint8_t> out(32, 0);
  for (int i = 0; i < 8; i++) out[31 - i] = (uint8_t)(value >> (8 * i));
  return out;
}

std::string amount(const std::vector<uint8_t>& value, const char* token,
                   bool native, uint64_t chain, const char* message = nullptr) {
  char out[600];
  const auto address = hex(token);
  if (!erc7730_format_token_amount(value.data(), address.data(), native, chain,
                                   message, out, sizeof(out)))
    return "<refused>";
  return out;
}

const char* kUsdc = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const char* kUnknown = "1111111111111111111111111111111111111111";

}  // namespace

// EIP-55's own test vectors.
TEST(Erc7730Field, AddressIsEip55AndMarksOnlyTheSigner) {
  char out[64];
  const auto a = hex("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
  ASSERT_TRUE(erc7730_format_address(a.data(), false, out, sizeof(out)));
  EXPECT_STREQ(out, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
  const auto b = hex("fb6916095ca1df60bb79ce92ce3ea74c37c5d359");
  ASSERT_TRUE(erc7730_format_address(b.data(), true, out, sizeof(out)));
  EXPECT_STREQ(out, "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359\n(this wallet)");
  EXPECT_FALSE(erc7730_format_address(b.data(), true, out, 43));
}

// Ticker and decimals come from the firmware table for the chain; the same
// address on another chain, the zero address and an unlisted address are
// unknown tokens, shown as the exact integer and the address.
TEST(Erc7730Field, TokenAmountUsesOnlyTheFirmwareTokenTable) {
  EXPECT_EQ(amount(word(1500000), kUsdc, false, 1), "1.5 USDC");
  EXPECT_EQ(amount(word(1500000), kUsdc, false, 137),
            "1500000\nunknown token\n0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
  EXPECT_EQ(amount(word(42), kUnknown, false, 1),
            "42\nunknown token\n0x1111111111111111111111111111111111111111");
  EXPECT_EQ(amount(word(42), "0000000000000000000000000000000000000000", false,
                   1),
            "42\nunknown token\n0x0000000000000000000000000000000000000000");
  // The largest amount still renders exactly.
  const std::vector<uint8_t> max(32, 0xff);
  EXPECT_EQ(amount(max, kUnknown, false, 1),
            "115792089237316195423570985008687907853269984665640564039457584007"
            "913129639935\nunknown token\n"
            "0x1111111111111111111111111111111111111111");
}

// A native alias is rendered as the ordinary review renders the value field.
TEST(Erc7730Field, NativeAliasUsesTheChainsNativeAsset) {
  EXPECT_EQ(amount(word(1500000000000000000ull), kUnknown, true, 1), "1.5 ETH");
  EXPECT_EQ(amount(word(1000), kUnknown, true, 1), "1000 Wei");
  // A chain without a native name here keeps the exact amount in wei.
  EXPECT_EQ(amount(word(1500000000000000000ull), kUnknown, true, 999999),
            "1500000000000000000 Wei");
}

// The signer's threshold message is shown above the value, never instead.
TEST(Erc7730Field, MessageNeverReplacesTheAmount) {
  EXPECT_EQ(amount(word(1500000), kUsdc, false, 1, "Unlimited"),
            "Unlimited\n1.5 USDC");
}

namespace {

void beginTokenAmount(Erc7730Workflow* workflow) {
  memset(workflow, 0, sizeof(*workflow));
  Erc7730Formatter formatter = {};
  formatter.kind = 3;
  formatter.argument_count = 3;
  formatter.arguments[0] = {1, 1, 1};
  formatter.arguments[1] = {2, 1, 0};
  formatter.arguments[2] = {7, 2, 0};
  ASSERT_TRUE(erc7730_workflow_field_begin(workflow, &formatter));
}

}  // namespace

TEST(Erc7730Field, TokenAmountArgumentsAreTypedAndOrdered) {
  static Erc7730Workflow workflow;
  beginTokenAmount(&workflow);
  const auto amount_word = word(1500000);
  // The threshold cannot precede the amount.
  workflow.field.pending_role = 7;
  const uint8_t threshold[] = {0x16, 0xe3, 0x60};  // 1,500,000
  EXPECT_FALSE(erc7730_workflow_field_value(&workflow, ERC7730_CLASS_UINT,
                                            threshold, sizeof(threshold)));
  // The amount must be an integer.
  workflow.field.pending_role = 1;
  EXPECT_FALSE(erc7730_workflow_field_value(&workflow, ERC7730_CLASS_ADDRESS,
                                            amount_word.data(), 32));
  EXPECT_TRUE(erc7730_workflow_field_value(&workflow, ERC7730_CLASS_UINT,
                                           amount_word.data(), 32));
  // A token word with a nonzero high byte is not an address.
  workflow.field.pending_role = 2;
  auto dirty = word(0);
  dirty[0] = 1;
  EXPECT_FALSE(erc7730_workflow_field_value(&workflow, ERC7730_CLASS_ADDRESS,
                                            dirty.data(), 32));
  const auto token = hex(kUsdc);
  EXPECT_TRUE(erc7730_workflow_field_value(&workflow, ERC7730_CLASS_ADDRESS,
                                           token.data(), 20));
  EXPECT_EQ(0, memcmp(workflow.field.token, token.data(), 20));
  // amount >= threshold, and one more than the amount is not reached.
  workflow.field.pending_role = 7;
  EXPECT_TRUE(erc7730_workflow_field_value(&workflow, ERC7730_CLASS_UINT,
                                           threshold, sizeof(threshold)));
  EXPECT_TRUE(workflow.field.threshold_reached);
  const uint8_t above[] = {0x16, 0xe3, 0x61};
  EXPECT_TRUE(erc7730_workflow_field_value(&workflow, ERC7730_CLASS_UINT,
                                           above, sizeof(above)));
  EXPECT_FALSE(workflow.field.threshold_reached);
  memset(&workflow, 0, sizeof(workflow));
}
