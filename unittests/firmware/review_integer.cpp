extern "C" {
#include "keepkey/firmware/eip712.h"
#include "trezor/crypto/sha3.h"
int encodableType(const char*);
int encodeBytes(const char*, uint8_t*);
int encodeBytesN(const char*, const char*, uint8_t*);
int parseVals(const json_t*, const json_t*, const json_t*, struct SHA3_CTX*);
}
#include "gtest/gtest.h"
#include <cstring>
#include <string>

bool kkconfirm_preload(int, int);
int kkconfirm_drain(void);

TEST(Eip712, MissingFieldRefusedWithoutDereferenceOrHashMutation) {
  char types[] = "{\"Review\":[{\"name\":\"value\",\"type\":\"int256\"}]}";
  char values[] = "{}";
  json_t tp[16], vp[8];
  const json_t* t = json_create(types, tp, 16);
  const json_t* v = json_create(values, vp, 8);
  ASSERT_NE(nullptr, t);
  ASSERT_NE(nullptr, v);
  SHA3_CTX ctx;
  sha3_256_Init(&ctx);
  const SHA3_CTX original = ctx;
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  EXPECT_EQ(JSON_TYPE_WNOVAL, parseVals(t, json_getProperty(t, "Review"),
                                      json_getChild(v), &ctx));
  EXPECT_EQ(0, memcmp(&ctx, &original, sizeof(ctx)));
  EXPECT_EQ(2, kkconfirm_drain());
}

TEST(Eip712, DecimalOverflowRefusedWithoutHashMutation) {
  for (const char* value : {"9223372036854775808", "-9223372036854775809",
                            "99999999999999999999999999999999999"}) {
    char types[] = "{\"Review\":[{\"name\":\"value\",\"type\":\"int256\"}]}";
    std::string values = std::string("{\"value\":\"") + value + "\"}";
    json_t tp[16], vp[8];
    const json_t* t = json_create(types, tp, 16);
    const json_t* v = json_create(&values[0], vp, 8);
    ASSERT_NE(nullptr, t);
    ASSERT_NE(nullptr, v);
    SHA3_CTX ctx;
    sha3_256_Init(&ctx);
    const SHA3_CTX original = ctx;
    ASSERT_TRUE(kkconfirm_preload(0, 1));
    EXPECT_EQ(GENERAL_ERROR, parseVals(t, json_getProperty(t, "Review"),
                                       json_getChild(v), &ctx));
    EXPECT_EQ(0, memcmp(&ctx, &original, sizeof(ctx)));
    EXPECT_EQ(2, kkconfirm_drain());
  }
}

TEST(Eip712, DecimalInt64BoundaryMatchesIndependentEncoding) {
  for (const char* value : {"9223372036854775807", "-9223372036854775808"}) {
    char types[] = "{\"Review\":[{\"name\":\"value\",\"type\":\"int256\"}]}";
    std::string values = std::string("{\"value\":\"") + value + "\"}";
    json_t tp[16], vp[8];
    const json_t* t = json_create(types, tp, 16);
    const json_t* v = json_create(&values[0], vp, 8);
    SHA3_CTX actual, expected;
    sha3_256_Init(&actual);
    sha3_256_Init(&expected);
    uint8_t bytes[32];
    memset(bytes, value[0] == '-' ? 0xff : 0, 24);
    bytes[24] = value[0] == '-' ? 0x80 : 0x7f;
    memset(bytes + 25, value[0] == '-' ? 0 : 0xff, 7);
    sha3_Update(&expected, bytes, sizeof(bytes));
    ASSERT_TRUE(kkconfirm_preload(1, 0));
    ASSERT_EQ(SUCCESS, parseVals(t, json_getProperty(t, "Review"),
                                 json_getChild(v), &actual));
    EXPECT_EQ(0, kkconfirm_drain());
    uint8_t a[32], e[32];
    keccak_Final(&actual, a);
    keccak_Final(&expected, e);
    EXPECT_EQ(0, memcmp(a, e, 32));
  }
}

TEST(Eip712, DecimalSignPaddingMatchesParsedValue) {
  for (const char* value : {"-0", " -1", "\t-1", "+0"}) {
    char types[] = "{\"Review\":[{\"name\":\"value\",\"type\":\"int256\"}]}";
    // JSON escapes the tab; the parser decodes it before integer conversion.
    std::string text = value[0] == '\t' ? "\\t-1" : value;
    std::string values = "{\"value\":\"" + text + "\"}";
    json_t tp[16], vp[8];
    const json_t* t = json_create(types, tp, 16);
    const json_t* v = json_create(&values[0], vp, 8);
    ASSERT_NE(nullptr, t);
    ASSERT_NE(nullptr, v);
    SHA3_CTX actual, expected;
    sha3_256_Init(&actual);
    sha3_256_Init(&expected);
    uint8_t bytes[32];
    memset(bytes, strchr(value, '1') ? 0xff : 0, sizeof(bytes));
    sha3_Update(&expected, bytes, sizeof(bytes));
    ASSERT_TRUE(kkconfirm_preload(1, 0));
    ASSERT_EQ(SUCCESS, parseVals(t, json_getProperty(t, "Review"),
                                 json_getChild(v), &actual));
    EXPECT_EQ(0, kkconfirm_drain());
    uint8_t a[32], e[32];
    keccak_Final(&actual, a);
    keccak_Final(&expected, e);
    EXPECT_EQ(0, memcmp(a, e, sizeof(a))) << text;
  }
}


TEST(Eip712, IntegerWidthAndValueMustMatchBeforeHashing) {
  struct Case { const char* type; const char* value; };
  const Case cases[] = {
      {"int8", "128"}, {"int8", "-129"}, {"uint8", "256"},
      {"uint8", "-1"}, {"int16", "32768"}, {"int16", "-32769"},
      {"uint16", "65536"}, {"int56", "36028797018963968"},
      {"uint56", "72057594037927936"}, {"int", "1"}, {"uint", "1"},
      {"int0", "1"}, {"int7", "1"}, {"int264", "1"}, {"int08", "1"},
      {"int256junk", "1"}, {"uint99999999999999999999", "1"},
  };
  for (const auto& c : cases) {
    SCOPED_TRACE(std::string(c.type) + ":" + c.value);
    std::string types = std::string("{\"Review\":[{\"name\":\"value\",\"type\":\"") +
                        c.type + "\"}]}";
    std::string values = std::string("{\"value\":\"") + c.value + "\"}";
    json_t tp[16], vp[8];
    const json_t* t = json_create(&types[0], tp, 16);
    const json_t* v = json_create(&values[0], vp, 8);
    ASSERT_NE(nullptr, t);
    ASSERT_NE(nullptr, v);
    SHA3_CTX ctx;
    sha3_256_Init(&ctx);
    const SHA3_CTX original = ctx;
    ASSERT_TRUE(kkconfirm_preload(0, 1));
    EXPECT_EQ(GENERAL_ERROR, parseVals(t, json_getProperty(t, "Review"),
                                       json_getChild(v), &ctx));
    EXPECT_EQ(0, memcmp(&ctx, &original, sizeof(ctx)));
    EXPECT_EQ(2, kkconfirm_drain());
  }
}

TEST(Eip712, NarrowIntegerBoundaryMatchesIndependentEncoding) {
  for (unsigned width = 8; width < 64; width += 8) {
    const int64_t bound = INT64_C(1) << (width - 1);
    for (int64_t value : {-bound, bound - 1, 2 * bound - 1}) {
      const bool is_unsigned = value == 2 * bound - 1;
      std::string type = (is_unsigned ? "uint" : "int") + std::to_string(width);
      std::string types = "{\"Review\":[{\"name\":\"value\",\"type\":\"" + type + "\"}]}";
      std::string values = "{\"value\":\"" + std::to_string(value) + "\"}";
      json_t tp[16], vp[8];
      const json_t* t = json_create(&types[0], tp, 16);
      const json_t* v = json_create(&values[0], vp, 8);
      ASSERT_NE(nullptr, t);
      ASSERT_NE(nullptr, v);
      SHA3_CTX actual, expected;
      sha3_256_Init(&actual);
      sha3_256_Init(&expected);
      uint8_t bytes[32];
      memset(bytes, value < 0 ? 0xff : 0, sizeof(bytes));
      const unsigned first = 32 - width / 8;
      if (value == -bound) {
        memset(bytes + first, 0, width / 8);
        bytes[first] = 0x80;
      } else {
        memset(bytes + first, 0xff, width / 8);
        if (!is_unsigned) bytes[first] = 0x7f;
      }
      sha3_Update(&expected, bytes, sizeof(bytes));
      ASSERT_TRUE(kkconfirm_preload(1, 0));
      ASSERT_EQ(SUCCESS, parseVals(t, json_getProperty(t, "Review"),
                                   json_getChild(v), &actual));
      EXPECT_EQ(0, kkconfirm_drain());
      uint8_t a[32], e[32];
      keccak_Final(&actual, a);
      keccak_Final(&expected, e);
      EXPECT_EQ(0, memcmp(a, e, sizeof(a))) << type << ":" << value;
    }
  }
}


TEST(Eip712, MalformedHexNeverPublishesEncodedOutput) {
  for (const char* value : {"", "0", "0x1", "0x123", "0xgg", "1234", "0x01zz"}) {
    uint8_t out[32];
    memset(out, 0xa5, sizeof(out));
    EXPECT_NE(SUCCESS, encodeBytes(value, out)) << value;
    for (uint8_t b : out) EXPECT_EQ(0xa5, b);
  }
  for (const char* type : {"bytes", "bytes0", "bytes33", "bytes256", "bytes01", "bytes1x"}) {
    uint8_t out[32];
    memset(out, 0xa5, sizeof(out));
    EXPECT_NE(SUCCESS, encodeBytesN(type, "0x01", out)) << type;
    for (uint8_t b : out) EXPECT_EQ(0xa5, b);
  }
  for (const char* value : {"", "0x", "0x1", "0x0102", "0xzz"}) {
    uint8_t out[32];
    memset(out, 0xa5, sizeof(out));
    EXPECT_NE(SUCCESS, encodeBytesN("bytes1", value, out)) << value;
    for (uint8_t b : out) EXPECT_EQ(0xa5, b);
  }
}

TEST(Eip712, ByteEncodingMatchesIndependentHashAndRightPadding) {
  for (unsigned width = 1; width <= 32; ++width) {
    const std::string type = "bytes" + std::to_string(width);
    std::string text = "0x";
    uint8_t expected[32] = {};
    for (unsigned i = 0; i < width; ++i) {
      text += "aB";
      expected[i] = 0xab;
    }
    uint8_t out[32];
    ASSERT_EQ(SUCCESS, encodeBytesN(type.c_str(), text.c_str(), out));
    EXPECT_EQ(0, memcmp(expected, out, sizeof(out)));
    SHA3_CTX ctx;
    sha3_256_Init(&ctx);
    sha3_Update(&ctx, expected, width);
    keccak_Final(&ctx, expected);
    ASSERT_EQ(SUCCESS, encodeBytes(text.c_str(), out));
    EXPECT_EQ(0, memcmp(expected, out, sizeof(out)));
  }
}

TEST(Eip712, MismatchedJsonShapesAndFixedArraysAreRejectedBeforeHashing) {
  struct Case { const char* type; const char* value; };
  const Case cases[] = {
      {"int256", "{}"}, {"uint256", "[]"}, {"string", "{}"},
      {"address", "[]"}, {"bytes1", "null"}, {"bool", "{}"},
      {"bool", "\"not a boolean\""}, {"", "\"x\""},
      {"string[]", "\"x\""}, {"string[2]", "[\"one\"]"},
      {"string[1]", "[\"one\",\"two\"]"},
      {"string[9999999999999999999]", "[]"}, {"string[0]", "[]"},
      {"stringevil", "\"x\""}, {"addressWrong", "\"x\""},
  };
  for (const auto& c : cases) {
    SCOPED_TRACE(std::string(c.type) + ":" + c.value);
    std::string types = std::string("{\"Review\":[{\"name\":\"value\",\"type\":\"") + c.type + "\"}]}";
    std::string values = std::string("{\"value\":") + c.value + "}";
    json_t tp[16], vp[16];
    const json_t* t = json_create(&types[0], tp, 16);
    const json_t* v = json_create(&values[0], vp, 16);
    ASSERT_NE(nullptr, t);
    ASSERT_NE(nullptr, v);
    SHA3_CTX ctx;
    sha3_256_Init(&ctx);
    const SHA3_CTX original = ctx;
    ASSERT_TRUE(kkconfirm_preload(0, 1));
    EXPECT_NE(SUCCESS, parseVals(t, json_getProperty(t, "Review"), json_getChild(v), &ctx));
    EXPECT_EQ(0, memcmp(&ctx, &original, sizeof(ctx)));
    EXPECT_EQ(2, kkconfirm_drain());
  }
}

TEST(Eip712, MalformedBytesAndAddressesRejectedBeforeAnyValueScreen) {
  struct Case { const char* type; const char* value; };
  const Case cases[] = {
      {"bytes", "\"0x1\""}, {"bytes", "\"0xzz\""}, {"bytes1", "\"0x0102\""},
      {"bytes1", "\"0xzz\""}, {"address", "\"0xzz\""},
      {"address[]", "[\"0x0000000000000000000000000000000000000001\",\"0xzz\"]"},
  };
  for (const auto& c : cases) {
    SCOPED_TRACE(std::string(c.type) + ":" + c.value);
    std::string types = std::string("{\"Review\":[{\"name\":\"value\",\"type\":\"") + c.type + "\"}]}";
    std::string values = std::string("{\"value\":") + c.value + "}";
    json_t tp[16], vp[16];
    const json_t* t = json_create(&types[0], tp, 16);
    const json_t* v = json_create(&values[0], vp, 16);
    ASSERT_NE(nullptr, t);
    ASSERT_NE(nullptr, v);
    SHA3_CTX ctx;
    sha3_256_Init(&ctx);
    const SHA3_CTX original = ctx;
    // A queued "No" must survive: no value screen may be shown for input
    // the encoder is going to reject.
    ASSERT_TRUE(kkconfirm_preload(0, 1));
    const int ret = parseVals(t, json_getProperty(t, "Review"), json_getChild(v), &ctx);
    EXPECT_NE(SUCCESS, ret);
    EXPECT_NE(USER_CANCELLED, ret);
    EXPECT_EQ(0, memcmp(&ctx, &original, sizeof(ctx)));
    EXPECT_EQ(2, kkconfirm_drain());
  }
}

TEST(Eip712, BytesNTypeWidthIsStrictInTypeHashAndEncoder) {
  // bytes288 used to wrap through uint8_t to 32 and enter the typehash.
  for (const char* type : {"bytes0", "bytes01", "bytes33", "bytes288", "bytes1x"})
    EXPECT_EQ(NOT_ENCODABLE, encodableType(type)) << type;
  for (const char* type : {"bytes1", "bytes32", "bytes32[]", "bytes"})
    EXPECT_NE(NOT_ENCODABLE, encodableType(type)) << type;
  uint8_t out[32];
  EXPECT_NE(SUCCESS, encodeBytesN("bytes288", "0x01", out));
}
