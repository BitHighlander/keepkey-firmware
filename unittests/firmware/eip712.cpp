extern "C" {
#include "keepkey/firmware/eip712.h"
#include "trezor/crypto/sha3.h"
}

#include "gtest/gtest.h"

#include <cstring>
#include <array>
#include <string>
#include "kkconfirm_driver.h"

TEST(EIP712, AddressRequiresCanonicalTwentyByteHex) {
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
  EXPECT_NE(SUCCESS, encAddress("0x00112233445566778899aabbccddeeff0011223344",
                                encoded));
}

TEST(EIP712, DynamicBytesRequireCompleteHexOctets) {
  uint8_t encoded[32] = {0};
  EXPECT_EQ(SUCCESS, encodeBytes("0x", encoded));
  EXPECT_EQ(SUCCESS, encodeBytes("0x00a1FF", encoded));
  EXPECT_NE(SUCCESS, encodeBytes("00a1", encoded));
  EXPECT_NE(SUCCESS, encodeBytes("0x0", encoded));
  EXPECT_NE(SUCCESS, encodeBytes("0x0z", encoded));
}

TEST(EIP712, FixedBytesRequireExactDeclaredLength) {
  uint8_t encoded[32];
  memset(encoded, 0xa5, sizeof(encoded));
  ASSERT_EQ(SUCCESS, encodeBytesN("bytes4", "0x0011aAff", encoded));
  EXPECT_EQ(0x00, encoded[0]);
  EXPECT_EQ(0x11, encoded[1]);
  EXPECT_EQ(0xaa, encoded[2]);
  EXPECT_EQ(0xff, encoded[3]);
  for (size_t i = 4; i < sizeof(encoded); i++) EXPECT_EQ(0, encoded[i]);

  EXPECT_NE(SUCCESS, encodeBytesN("bytes4", "0x0011aa", encoded));
  EXPECT_NE(SUCCESS, encodeBytesN("bytes4", "0x0011aaff00", encoded));
  EXPECT_NE(SUCCESS, encodeBytesN("bytes0", "0x", encoded));
  EXPECT_NE(SUCCESS, encodeBytesN("bytes33", "0x", encoded));
  EXPECT_NE(SUCCESS, encodeBytesN("bytes4294967297", "0x00", encoded));
  EXPECT_NE(SUCCESS, encodeBytesN("bytes4x", "0x0011aaff", encoded));
}

TEST(EIP712, IntegerWidthsCannotWrapIntoValidTypes) {
  char types_json[] =
      "{\"types\":{\"Test\":[{\"name\":\"value\","
      "\"type\":\"uint4294967552\"}]}}";
  char values_json[] = "{\"message\":{\"value\":\"1\"}}";
  json_t type_nodes[12] = {};
  json_t value_nodes[8] = {};
  const json_t* types = json_create(types_json, type_nodes, 12);
  const json_t* values = json_create(values_json, value_nodes, 8);
  ASSERT_NE(nullptr, types);
  ASSERT_NE(nullptr, values);

  uint8_t hash[32] = {};
  EXPECT_NE(SUCCESS, encode(types, values, "Test", hash));
}

TEST(EIP712, FixedStructArraysRequireExactCardinality) {
  char types_json[] =
      "{\"types\":{"
      "\"Person\":[{\"name\":\"name\",\"type\":\"string\"}],"
      "\"Group\":[{\"name\":\"members\",\"type\":\"Person[2]\"}]}}";
  char too_few_json[] = "{\"message\":{\"members\":[{\"name\":\"Alice\"}]}}";
  char too_many_json[] =
      "{\"message\":{\"members\":[{\"name\":\"Alice\"},"
      "{\"name\":\"Bob\"},{\"name\":\"Carol\"}]}}";
  json_t type_nodes[24] = {};
  json_t too_few_nodes[12] = {};
  json_t too_many_nodes[20] = {};
  const json_t* types = json_create(types_json, type_nodes, 24);
  const json_t* too_few = json_create(too_few_json, too_few_nodes, 12);
  const json_t* too_many = json_create(too_many_json, too_many_nodes, 20);
  ASSERT_NE(nullptr, types);
  ASSERT_NE(nullptr, too_few);
  ASSERT_NE(nullptr, too_many);

  uint8_t hash[32] = {};
  EXPECT_NE(SUCCESS, encode(types, too_few, "Group", hash));
  EXPECT_NE(SUCCESS, encode(types, too_many, "Group", hash));
}

TEST(EIP712, MissingTypedValueFailsWithoutDereferencingNull) {
  char types_json[] =
      "{\"types\":{\"Mail\":[{\"name\":\"from\",\"type\":\"address\"},"
      "{\"name\":\"note\",\"type\":\"string\"}]}}";
  char values_json[] = "{\"message\":{\"note\":\"hello\"}}";
  json_t type_nodes[16] = {};
  json_t value_nodes[8] = {};
  const json_t* types = json_create(types_json, type_nodes, 16);
  const json_t* values = json_create(values_json, value_nodes, 8);
  ASSERT_NE(nullptr, types);
  ASSERT_NE(nullptr, values);

  uint8_t hash[32] = {};
  EXPECT_EQ(JSON_TYPE_WNOVAL, encode(types, values, "Mail", hash));
}

TEST(EIP712, ShortByteStringsFailClosed) {
  uint8_t output[32] = {};
  const char empty[] = {'\0'};
  const char zero[] = {'0', '\0'};
  for (const char* value : {empty, zero, "x", "0X"}) {
    EXPECT_NE(SUCCESS, encodeBytes(value, output));
    EXPECT_NE(SUCCESS, encodeBytesN("bytes1", value, output));
  }
}

static int encodeDomainField(const char* field, const char* value) {
  std::string types = "{\"types\":{\"EIP712Domain\":[{\"name\":\"";
  types += field;
  types += "\",\"type\":\"string\"}]}}";
  std::string values = "{\"domain\":{\"";
  values += field;
  values += "\":\"";
  values += value;
  values += "\"}}";
  json_t type_nodes[16] = {}, value_nodes[8] = {};
  const json_t* t = json_create(&types[0], type_nodes, 16);
  const json_t* v = json_create(&values[0], value_nodes, 8);
  if (!t || !v) return GENERAL_ERROR;
  uint8_t hash[32] = {};
  return encode(t, v, "EIP712Domain", hash);
}

TEST(EIP712, DomainContractValidatesEvenWhenDeclaredString) {
  for (const char* value :
       {"", "0", "0x01", "0x00112233445566778899aabbccddeeff0011223g"}) {
    ASSERT_TRUE(kkconfirm_preload(2, 0));
    EXPECT_EQ(ADDR_STRING_VFLOW, encodeDomainField("verifyingContract", value));
    kkconfirm_drain();
  }
}

TEST(EIP712, DomainChainIdRejectsNoncanonicalAndOverflowValues) {
  for (const char* value : {"", "01", "+1", "-1", "1x", "4294967296"}) {
    ASSERT_TRUE(kkconfirm_preload(2, 0));
    EXPECT_EQ(GENERAL_ERROR, encodeDomainField("chainId", value));
    kkconfirm_drain();
  }
  ASSERT_TRUE(kkconfirm_preload(3, 0));
  EXPECT_EQ(SUCCESS, encodeDomainField("chainId", "4294967295"));
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(EIP712, DomainSummaryCancellationIsNotApproval) {
  ASSERT_TRUE(kkconfirm_preload(2, 1));
  EXPECT_EQ(USER_CANCELLED, encodeDomainField("chainId", "1"));
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(EIP712, FailedDomainCannotRetainPointersIntoPriorJson) {
  ASSERT_TRUE(kkconfirm_preload(1, 1));
  EXPECT_EQ(USER_CANCELLED, encodeDomainField("verifyingContract", "0x01"));
  EXPECT_EQ(0, kkconfirm_drain());
  // Previous field has been marshalled, then cancelled, and its JSON freed.
  // The next domain omits it and must not reuse the invalid/dangling pointer.
  ASSERT_TRUE(kkconfirm_preload(3, 0));
  EXPECT_EQ(SUCCESS, encodeDomainField("chainId", "1"));
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(EIP712, IntegerValuesRejectNoncanonicalDecimal) {
  char types_json[] =
      "{\"types\":{\"Test\":[{\"name\":\"value\",\"type\":\"int64\"}]}}";
  json_t type_nodes[12] = {};
  const json_t* types = json_create(types_json, type_nodes, 12);
  ASSERT_NE(nullptr, types);
  for (const char* value : {"01", "-0", "-01", "+1", "1x"}) {
    std::string text = "{\"message\":{\"value\":\"";
    text += value;
    text += "\"}}";
    json_t value_nodes[8] = {};
    const json_t* values = json_create(&text[0], value_nodes, 8);
    ASSERT_NE(nullptr, values);
    ASSERT_TRUE(kkconfirm_preload(2, 0));
    uint8_t hash[32] = {};
    EXPECT_EQ(GENERAL_ERROR, encode(types, values, "Test", hash));
    EXPECT_EQ(0, kkconfirm_drain());
  }
}

TEST(EIP712, PublicTinyJsonErrorStatusRemainsLinkable) {
  const volatile int* parser_status = &json_errno;
  EXPECT_NE(nullptr, parser_status);
}

TEST(EIP712, CanonicalIntegerWidthsMatchIndependentAbiWords) {
  struct Case {
    const char* type;
    const char* text;
    bool valid;
    uint8_t first;
    uint8_t last;
    uint8_t fill;
    size_t fill_start;
  };
  const Case cases[] = {
      {"uint64", "9223372036854775808", true, 0, 0, 0, 32},
      {"uint64", "18446744073709551615", true, 0, 0xff, 0xff, 24},
      {"uint64", "18446744073709551616", false, 0, 0, 0, 32},
      {"uint128", "340282366920938463463374607431768211455", true, 0, 0xff,
       0xff, 16},
      {"uint128", "340282366920938463463374607431768211456", false, 0, 0, 0,
       32},
      {"uint256",
       "11579208923731619542357098500868790785326998466564056403945758400791312"
       "9639935",
       true, 0xff, 0xff, 0xff, 0},
      {"uint256",
       "11579208923731619542357098500868790785326998466564056403945758400791312"
       "9639936",
       false, 0, 0, 0, 32},
      {"int256",
       "57896044618658097711785492504343953926634992332820282019728792003956564"
       "819967",
       true, 0x7f, 0xff, 0xff, 1},
      {"int256",
       "57896044618658097711785492504343953926634992332820282019728792003956564"
       "819968",
       false, 0, 0, 0, 32},
      {"int256",
       "-5789604461865809771178549250434395392663499233282028201972879200395656"
       "4819968",
       true, 0x80, 0, 0, 1},
      {"int256",
       "-5789604461865809771178549250434395392663499233282028201972879200395656"
       "4819969",
       false, 0, 0, 0, 32},
      {"int8", "127", true, 0, 0x7f, 0, 32},
      {"int8", "128", false, 0, 0, 0, 32},
      {"int8", "-128", true, 0xff, 0x80, 0xff, 0},
      {"int8", "-129", false, 0, 0, 0, 32},
      {"uint8", "255", true, 0, 0xff, 0, 32},
      {"uint8", "256", false, 0, 0, 0, 32},
      {"uint256", "01", false, 0, 0, 0, 32},
      {"int256", "-0", false, 0, 0, 0, 32},
  };
  for (const Case& c : cases) {
    SCOPED_TRACE(std::string(c.type) + " = " + c.text);
    std::string type_json =
        std::string("{\"types\":{\"Test\":[{\"name\":\"value\",\"type\":\"") +
        c.type + "\"}]}}";
    std::string value_json =
        std::string("{\"message\":{\"value\":\"") + c.text + "\"}}";
    json_t type_nodes[12] = {}, value_nodes[8] = {};
    const json_t* types = json_create(&type_json[0], type_nodes, 12);
    const json_t* values = json_create(&value_json[0], value_nodes, 8);
    ASSERT_NE(nullptr, types);
    ASSERT_NE(nullptr, values);
    ASSERT_TRUE(kkconfirm_preload(2, 0));
    uint8_t actual[32] = {};
    const int status = encode(types, values, "Test", actual);
    EXPECT_EQ(c.valid ? SUCCESS : GENERAL_ERROR, status);
    EXPECT_EQ(0, kkconfirm_drain());
    if (!c.valid || status != SUCCESS) continue;

    std::array<uint8_t, 32> word = {};
    word.fill(0);
    for (size_t i = c.fill_start; i < word.size(); ++i) word[i] = c.fill;
    word[0] = c.first;
    word[31] = c.last;
    if (strcmp(c.type, "uint64") == 0 && c.text[0] == '9') word[24] = 0x80;
    if (strcmp(c.type, "int8") == 0 && c.text[0] == '-') {
      for (size_t i = 0; i < 31; ++i) word[i] = 0xff;
    }
    const std::string type_string = std::string("Test(") + c.type + " value)";
    uint8_t type_hash[32], expected[32];
    keccak_256(reinterpret_cast<const uint8_t*>(type_string.data()),
               type_string.size(), type_hash);
    SHA3_CTX ctx = {};
    sha3_256_Init(&ctx);
    sha3_Update(&ctx, type_hash, sizeof(type_hash));
    sha3_Update(&ctx, word.data(), word.size());
    keccak_Final(&ctx, expected);
    EXPECT_EQ(0, memcmp(actual, expected, sizeof(actual)));
  }
}

TEST(EIP712, DomainAcceptsChainIdAboveThirtyTwoBits) {
  char types_json[] =
      "{\"types\":{\"EIP712Domain\":["
      "{\"name\":\"name\",\"type\":\"string\"},"
      "{\"name\":\"chainId\",\"type\":\"uint256\"}]}}";
  char values_json[] =
      "{\"domain\":{\"name\":\"Palm\",\"chainId\":\"11297108109\"}}";
  json_t type_nodes[24] = {};
  json_t value_nodes[12] = {};
  const json_t* types = json_create(types_json, type_nodes, 24);
  const json_t* values = json_create(values_json, value_nodes, 12);
  ASSERT_NE(nullptr, types);
  ASSERT_NE(nullptr, values);

  uint8_t hash[32] = {};
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_EQ(SUCCESS, encode(types, values, "EIP712Domain", hash));
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(EIP712, DomainRejectsNonCanonicalChainId) {
  char types_json[] =
      "{\"types\":{\"EIP712Domain\":["
      "{\"name\":\"chainId\",\"type\":\"uint256\"}]}}";
  char values_json[] = "{\"domain\":{\"chainId\":\"007\"}}";
  json_t type_nodes[16] = {};
  json_t value_nodes[8] = {};
  const json_t* types = json_create(types_json, type_nodes, 16);
  const json_t* values = json_create(values_json, value_nodes, 8);
  ASSERT_NE(nullptr, types);
  ASSERT_NE(nullptr, values);

  uint8_t hash[32] = {};
  EXPECT_EQ(GENERAL_ERROR, encode(types, values, "EIP712Domain", hash));
}
