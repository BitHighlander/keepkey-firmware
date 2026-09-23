extern "C" {
#include "keepkey/firmware/eip712.h"
#include "trezor/crypto/sha3.h"
int parseVals(const json_t*, const json_t*, const json_t*, struct SHA3_CTX*);
}
#include "gtest/gtest.h"
#include <cstring>
#include <string>

bool kkconfirm_preload(int, int);
int kkconfirm_drain(void);

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
