extern "C" {
#include "keepkey/firmware/eip712.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_contracts.h"
#include "keepkey/firmware/ethereum_contracts/zxtransERC20.h"
#include "keepkey/firmware/tron.h"
#include "trezor/crypto/address.h"
#include "messages-ethereum.pb.h"
}

#include "gtest/gtest.h"

#include <cstring>
#include <string>

static uint8_t bin_from_ascii(char c) {
  if ('a' <= c && c <= 'f') return c - 'a' + 0xa;

  if ('A' <= c && c <= 'F') return c - 'A' + 0xA;

  if ('0' <= c && c <= '9') return c - '0' + 0x0;

  __builtin_unreachable();
}

static void test_checksum(const std::string& addr) {
  uint8_t addr_bin[20];
  for (size_t i = 0; i < addr.size(); i += 2) {
    addr_bin[i / 2] = bin_from_ascii(addr[i + 1]) | bin_from_ascii(addr[i])
                                                        << 4;
  }

  char formatted[41];
  ethereum_address_checksum(addr_bin, formatted, false, 0);

  ASSERT_EQ(formatted[40], '\0') << "Must be null terminated";

  ASSERT_EQ(addr, std::string(formatted)) << "Checksum mismatch";
}

TEST(Ethereum, AddressChecksum) {
  // Testcases from: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
  test_checksum("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
  test_checksum("fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
  test_checksum("dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB");
  test_checksum("D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb");
}

TEST(Ethereum, Eip712AddressRequiresCanonicalTwentyByteHex) {
  uint8_t encoded[32] = {0};
  ASSERT_EQ(SUCCESS,
            encAddress("0x00112233445566778899aabbccddeeff00112233", encoded));
  for (size_t i = 0; i < 12; i++) EXPECT_EQ(0, encoded[i]);
  EXPECT_EQ(0x00, encoded[12]);
  EXPECT_EQ(0x11, encoded[13]);
  EXPECT_EQ(0x33, encoded[31]);

  EXPECT_NE(SUCCESS, encAddress("0x112233", encoded));
  EXPECT_NE(SUCCESS,
            encAddress("00112233445566778899aabbccddeeff00112233", encoded));
  EXPECT_NE(SUCCESS,
            encAddress("0x00112233445566778899aabbccddeeff0011223g", encoded));
  EXPECT_NE(SUCCESS, encAddress(
                         "0x00112233445566778899aabbccddeeff0011223344",
                         encoded));
}

// Every EIP-712 field screen used to be a review(), which calls
// confirm_helper() and then returns true unconditionally, so a host that
// answered each screen with a protocol Cancel still got a hash back. The
// screens are confirm() now and refusal reaches ethereum.c as USER_CANCELLED.
//
// That code has to stay outside failMsgReturn[]. ethereum.c sizes the table
// LAST_ERROR - 2 and indexes it err - 3, so a cancellation code at or below
// LAST_ERROR would shift every message already in the table and would make
// failMessage() report a refusal as a parse error instead of an
// ActionCancelled. It also must not collide with the two non-error codes.
TEST(Ethereum, Eip712UserCancelledIsOutsideTheFailMessageTable) {
  EXPECT_GT(USER_CANCELLED, LAST_ERROR);
  EXPECT_NE(USER_CANCELLED, SUCCESS);
  EXPECT_NE(USER_CANCELLED, NULL_MSG_HASH);
}

TEST(Ethereum, PrecomputedTypedHashesRequireAdvancedMode) {
  EXPECT_FALSE(ethereum_typed_hash_policy_allows(false));
  EXPECT_TRUE(ethereum_typed_hash_policy_allows(true));
  EXPECT_FALSE(tron_typed_hash_policy_allows(false));
  EXPECT_TRUE(tron_typed_hash_policy_allows(true));
}

TEST(Ethereum, StructuredEip712EnablesBoundedCanonicalSubset) {
  EXPECT_TRUE(ethereum_structured_eip712_enabled());
}

TEST(Ethereum, StructuredEip712AcceptsCanonicalFlatDomain) {
  char types_json[] =
      "{\"types\":{\"EIP712Domain\":["
      "{\"name\":\"name\",\"type\":\"string\"},"
      "{\"name\":\"chainId\",\"type\":\"uint256\"},"
      "{\"name\":\"verifyingContract\",\"type\":\"address\"},"
      "{\"name\":\"salt\",\"type\":\"bytes32\"}]}}";
  char values_json[] =
      "{\"domain\":{\"name\":\"KeepKey\",\"chainId\":1,"
      "\"verifyingContract\":\"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC\","
      "\"salt\":"
      "\"0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}"
      "}";
  json_t type_nodes[24] = {};
  json_t value_nodes[16] = {};
  const json_t* types = json_create(types_json, type_nodes, 24);
  const json_t* values = json_create(values_json, value_nodes, 16);
  ASSERT_NE(nullptr, types);
  ASSERT_NE(nullptr, values);
  EXPECT_TRUE(eip712_document_is_supported(types, values, "EIP712Domain"));
}

TEST(Ethereum, StructuredEip712AcceptsFlatPermitMessage) {
  char types_json[] =
      "{\"types\":{\"Permit\":["
      "{\"name\":\"owner\",\"type\":\"address\"},"
      "{\"name\":\"spender\",\"type\":\"address\"},"
      "{\"name\":\"value\",\"type\":\"uint256\"},"
      "{\"name\":\"nonce\",\"type\":\"uint256\"},"
      "{\"name\":\"deadline\",\"type\":\"uint256\"}]}}";
  char values_json[] =
      "{\"message\":{"
      "\"owner\":\"0x00112233445566778899aabbccddeeff00112233\","
      "\"spender\":\"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC\","
      "\"value\":\"1000000000000000000\",\"nonce\":0,"
      "\"deadline\":\"1700000000\"}}";
  json_t type_nodes[28] = {};
  json_t value_nodes[20] = {};
  const json_t* types = json_create(types_json, type_nodes, 28);
  const json_t* values = json_create(values_json, value_nodes, 20);
  ASSERT_NE(nullptr, types);
  ASSERT_NE(nullptr, values);
  EXPECT_TRUE(eip712_document_is_supported(types, values, "Permit"));
}

TEST(Ethereum, StructuredEip712RejectsUnprovenShapesAndValues) {
  struct TestCase {
    const char* types;
    const char* values;
    const char* primary_type;
  } cases[] = {
      // Nested structs remain on the AdvancedMode typed-hash path.
      {"{\"types\":{\"Mail\":[{\"name\":\"from\",\"type\":\"Person\"}]}}",
       "{\"message\":{\"from\":{\"name\":\"Alice\"}}}", "Mail"},
      // Arrays are not in the bounded point-release subset.
      {"{\"types\":{\"List\":[{\"name\":\"items\",\"type\":\"string[]\"}]}}",
       "{\"message\":{\"items\":[\"one\"]}}", "List"},
      // Values not declared by the schema would be signed invisibly if they
      // were merely ignored.
      {"{\"types\":{\"Note\":[{\"name\":\"text\",\"type\":\"string\"}]}}",
       "{\"message\":{\"text\":\"hello\",\"hidden\":\"tail\"}}", "Note"},
      // Duplicate declarations cannot be used to balance an extra value.
      {"{\"types\":{\"Note\":[{\"name\":\"text\",\"type\":\"string\"},"
       "{\"name\":\"text\",\"type\":\"string\"}]}}",
       "{\"message\":{\"text\":\"hello\",\"hidden\":\"tail\"}}", "Note"},
      // Text is not accepted as a boolean, even when it reads like one.
      {"{\"types\":{\"Flag\":[{\"name\":\"ok\",\"type\":\"bool\"}]}}",
       "{\"message\":{\"ok\":\"false\"}}", "Flag"},
      // Integer strings have one canonical spelling.
      {"{\"types\":{\"Count\":[{\"name\":\"n\",\"type\":\"uint8\"}]}}",
       "{\"message\":{\"n\":\"01\"}}", "Count"},
      {"{\"types\":{\"Count\":[{\"name\":\"n\",\"type\":\"uint8\"}]}}",
       "{\"message\":{\"n\":\"256\"}}", "Count"},
      // The released encoder is intentionally bounded to signed 64-bit input.
      {"{\"types\":{\"Count\":[{\"name\":\"n\",\"type\":\"uint256\"}]}}",
       "{\"message\":{\"n\":\"9223372036854775808\"}}", "Count"},
      // Fixed bytes must contain exactly the declared number of octets.
      {"{\"types\":{\"Blob\":[{\"name\":\"data\",\"type\":\"bytes4\"}]}}",
       "{\"message\":{\"data\":\"0x0011aa\"}}", "Blob"},
  };

  for (const auto& test : cases) {
    char types_json[256] = {0};
    char values_json[256] = {0};
    ASSERT_LT(strlen(test.types), sizeof(types_json));
    ASSERT_LT(strlen(test.values), sizeof(values_json));
    strcpy(types_json, test.types);
    strcpy(values_json, test.values);
    json_t type_nodes[20] = {};
    json_t value_nodes[20] = {};
    const json_t* types = json_create(types_json, type_nodes, 20);
    const json_t* values = json_create(values_json, value_nodes, 20);
    ASSERT_NE(nullptr, types);
    ASSERT_NE(nullptr, values);
    EXPECT_FALSE(
        eip712_document_is_supported(types, values, test.primary_type));
  }
}

TEST(Ethereum, StructuredEip712DomainOnlyRequiresAnEmptyMessageObject) {
  char valid_json[] = "{\"message\":{}}";
  char extra_json[] = "{\"message\":{},\"other\":{}}";
  char nonempty_json[] = "{\"message\":{\"hidden\":1}}";
  json_t valid_nodes[4] = {};
  json_t extra_nodes[8] = {};
  json_t nonempty_nodes[8] = {};
  EXPECT_TRUE(eip712_empty_message_is_supported(
      json_create(valid_json, valid_nodes, 4)));
  EXPECT_FALSE(eip712_empty_message_is_supported(
      json_create(extra_json, extra_nodes, 8)));
  EXPECT_FALSE(eip712_empty_message_is_supported(
      json_create(nonempty_json, nonempty_nodes, 8)));
}

TEST(Ethereum, StructuredEip712BytesRejectMalformedHex) {
  uint8_t encoded[32] = {0};
  EXPECT_EQ(SUCCESS, encodeBytes("0x00a1FF", encoded));
  EXPECT_NE(SUCCESS, encodeBytes("00a1", encoded));
  EXPECT_NE(SUCCESS, encodeBytes("0x0", encoded));
  EXPECT_NE(SUCCESS, encodeBytes("0x0z", encoded));

  EXPECT_EQ(SUCCESS, encodeBytesN("bytes4", "0x0011aAff", encoded));
  EXPECT_NE(SUCCESS, encodeBytesN("bytes4", "0x0011aa", encoded));
  EXPECT_NE(SUCCESS, encodeBytesN("bytes4", "0x0011aaff00", encoded));
  EXPECT_NE(SUCCESS, encodeBytesN("bytes0", "0x", encoded));
  EXPECT_NE(SUCCESS, encodeBytesN("bytes33", "0x", encoded));
}

TEST(Ethereum, StructuredEip712RejectsUnicodeEscapesTinyJsonCannotDecode) {
  EXPECT_TRUE(eip712_json_is_supported("{\"message\":{\"text\":\"hello\"}}"));
  EXPECT_TRUE(
      eip712_json_is_supported("{\"message\":{\"text\":\"caf\xC3\xA9\"}}"));
  EXPECT_FALSE(
      eip712_json_is_supported("{\"message\":{\"text\":\"\\u00e9\"}}"));
}

// Two real chain-1 table entries, so the decoder's token lookups resolve.
// The table has no chain-1 zero-address entry, so an all-zero word is a
// reliable "unknown token".
static const char kTUSD[] =
    "\x00\x00\x00\x00\x00\x08\x5d\x47\x80\xB7\x31\x19\xb6\x44\xAE\x5e\xcd\x22"
    "\xb3\x76";
static const char kTGBP[] =
    "\x00\x00\x00\x00\x44\x13\x78\x00\x8E\xA6\x7F\x42\x84\xA5\x79\x32\xB1\xc0"
    "\x00\xa5";

// transformERC20(address,address,uint256,uint256,(uint32,bytes)[]) — the two
// address words carry the token in their low 20 bytes.
static void MakeTransformErc20(EthereumSignTx* msg, const char* in_token,
                               const char* out_token) {
  *msg = EthereumSignTx{};
  msg->has_to = true;
  msg->to.size = 20;
  std::memcpy(msg->to.bytes, ZXSWAP_ADDRESS, msg->to.size);
  msg->has_chain_id = true;
  msg->chain_id = 1;
  msg->has_data_initial_chunk = true;
  msg->data_initial_chunk.size = 4 + 4 * 32;
  std::memcpy(msg->data_initial_chunk.bytes, "\x41\x55\x65\xb0", 4);
  if (in_token) std::memcpy(msg->data_initial_chunk.bytes + 4 + 12, in_token, 20);
  if (out_token)
    std::memcpy(msg->data_initial_chunk.bytes + 4 + 32 + 12, out_token, 20);
}

TEST(Ethereum, TransformErc20RequiresCompleteCalldataForClearSigning) {
  EthereumSignTx msg;
  MakeTransformErc20(&msg, kTUSD, kTGBP);

  EXPECT_TRUE(
      ethereum_contractHandled(msg.data_initial_chunk.size, &msg, nullptr));
  EXPECT_FALSE(
      ethereum_contractHandled(msg.data_initial_chunk.size + 1, &msg, nullptr));
}

// The decoder shows four values and hides the transformations[] body. That is
// only defensible because the input amount and minimum output amount bound the
// outcome — and ethereumFormatAmount() renders the literal "Unknown token
// value" whenever tokenByChainAddress() misses, so an unresolved token turns
// the bound into nothing while the calldata still executes.
//
// Gating on the lookup rather than on a chain allowlist keeps this correct
// however the tables change. It matters in practice: the generated table
// carries ~1924 entries for chain 1, three each for BSC and Polygon, and NONE
// for Base, Arbitrum or Avalanche, so on those chains every pair fails here.
TEST(Ethereum, TransformErc20RequiresBothTokensResolvable) {
  EthereumSignTx msg;

  // Both known -> the device can name what it is showing.
  MakeTransformErc20(&msg, kTUSD, kTGBP);
  EXPECT_TRUE(ethereum_contractHandled(msg.data_initial_chunk.size, &msg,
                                       nullptr));

  // Either side unknown -> refuse to claim it, so ethereum.c falls through to
  // the raw-calldata path (AdvancedMode-gated, bytes shown).
  MakeTransformErc20(&msg, nullptr, kTGBP);
  EXPECT_FALSE(ethereum_contractHandled(msg.data_initial_chunk.size, &msg,
                                        nullptr))
      << "unknown INPUT token must not clear-sign";

  MakeTransformErc20(&msg, kTUSD, nullptr);
  EXPECT_FALSE(ethereum_contractHandled(msg.data_initial_chunk.size, &msg,
                                        nullptr))
      << "unknown OUTPUT token must not clear-sign";

  MakeTransformErc20(&msg, nullptr, nullptr);
  EXPECT_FALSE(ethereum_contractHandled(msg.data_initial_chunk.size, &msg,
                                        nullptr));

  // A chain with no token table entries at all cannot name either asset, so it
  // must refuse even though 0x deploys the same proxy there. This is what the
  // chain allowlist was previously being asked to approximate.
  for (uint32_t cid : {8453u, 42161u, 43114u}) {
    MakeTransformErc20(&msg, kTUSD, kTGBP);
    msg.chain_id = cid;
    EXPECT_FALSE(ethereum_contractHandled(msg.data_initial_chunk.size, &msg,
                                          nullptr))
        << "chain " << cid << " has no token entries; nothing is nameable";
  }
}

TEST(Ethereum, Eip712ChainIdRequiresCanonicalUint32) {
  uint32_t value = 0;
  EXPECT_TRUE(eip712_parse_canonical_u32("0", &value));
  EXPECT_EQ(0u, value);
  EXPECT_TRUE(eip712_parse_canonical_u32("4294967295", &value));
  EXPECT_EQ(UINT32_MAX, value);

  EXPECT_FALSE(eip712_parse_canonical_u32("", &value));
  EXPECT_FALSE(eip712_parse_canonical_u32("01", &value));
  EXPECT_FALSE(eip712_parse_canonical_u32("-1", &value));
  EXPECT_FALSE(eip712_parse_canonical_u32("1 ", &value));
  EXPECT_FALSE(eip712_parse_canonical_u32("4294967296", &value));
  EXPECT_FALSE(eip712_parse_canonical_u32(nullptr, &value));
  EXPECT_FALSE(eip712_parse_canonical_u32("1", nullptr));
}

extern "C" {
#include "keepkey/firmware/ethereum_contracts.h"
}

// The 0x Exchange Proxy lives at the same address on many chains, so the two 0x
// decoders cannot be pinned to mainnet the way the Uniswap and Sablier ones are.
// Optimism is the trap: 0x deploys a DIFFERENT proxy there
// (0xdef1abe32c034e558cdd535791643c58a13acc10), so allowing chain 10 for
// ZXSWAP_ADDRESS would narrate an unrelated contract.
TEST(Ethereum, ZxExchangeProxyChainAllowlist) {
  EXPECT_TRUE(zx_isExchangeProxyChain(1));      // Ethereum
  EXPECT_TRUE(zx_isExchangeProxyChain(56));     // BNB Chain
  EXPECT_TRUE(zx_isExchangeProxyChain(137));    // Polygon
  EXPECT_TRUE(zx_isExchangeProxyChain(8453));   // Base
  EXPECT_TRUE(zx_isExchangeProxyChain(42161));  // Arbitrum
  EXPECT_TRUE(zx_isExchangeProxyChain(43114));  // Avalanche

  EXPECT_FALSE(zx_isExchangeProxyChain(10)) << "Optimism uses a different 0x proxy";

  // Default-deny: anything unlisted falls through to generic disclosure.
  EXPECT_FALSE(zx_isExchangeProxyChain(0));
  EXPECT_FALSE(zx_isExchangeProxyChain(5));
  EXPECT_FALSE(zx_isExchangeProxyChain(250));
  EXPECT_FALSE(zx_isExchangeProxyChain(59144));
  EXPECT_FALSE(zx_isExchangeProxyChain(0xFFFFFFFFu));
}
