extern "C" {
#include "keepkey/firmware/ton.h"
}

#include "gtest/gtest.h"
#include <cstring>

/* Only workchains 0 and -1 exist. The base64 form encodes a single workchain
 * byte while raw_address prints the full int32, so anything else would return
 * two disagreeing representations of "the same" address. */
TEST(Ton, GetAddressRejectsOutOfRangeWorkchain) {
  ed25519_public_key pk;
  memset(pk, 0x42, sizeof(pk));
  char address[TON_ADDRESS_MAX_LEN];
  char raw[TON_RAW_ADDRESS_MAX_LEN];

  EXPECT_TRUE(ton_get_address(pk, true, false, 0, address, sizeof(address),
                              raw, sizeof(raw)));
  EXPECT_EQ(strncmp(raw, "0:", 2), 0);
  EXPECT_TRUE(ton_get_address(pk, true, false, -1, address, sizeof(address),
                              raw, sizeof(raw)));
  EXPECT_EQ(strncmp(raw, "-1:", 3), 0);

  EXPECT_FALSE(ton_get_address(pk, true, false, 256, address,
                               sizeof(address), raw, sizeof(raw)));
  EXPECT_FALSE(ton_get_address(pk, true, false, 1, address, sizeof(address),
                               raw, sizeof(raw)));
  EXPECT_FALSE(ton_get_address(pk, true, false, -2, address, sizeof(address),
                               raw, sizeof(raw)));
}

/* The blind-sign screen shows sha256(raw_tx) so equal-length payload swaps
 * are visible on-device. */
TEST(Ton, BlindSignDigestIsSha256OfRawTx) {
  char hex[65];
  ton_formatRawTxDigest(reinterpret_cast<const uint8_t*>("abc"), 3, hex,
                        sizeof(hex));
  EXPECT_STREQ(
      hex,
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

  char small[8] = "xx";
  ton_formatRawTxDigest(reinterpret_cast<const uint8_t*>("abc"), 3, small,
                        sizeof(small));
  EXPECT_STREQ(small, "");
}
