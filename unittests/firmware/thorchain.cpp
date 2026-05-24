extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/thorchain.h"
#include "keepkey/firmware/tendermint.h"
#include "trezor/crypto/secp256k1.h"
}

#include "gtest/gtest.h"
#include <cstring>

// Vectors computed with the trezor-crypto library directly (see
// unittests/firmware/thorchain.cpp notes). The test file was previously
// absent from CMakeLists.txt so none of these values were ever validated;
// all expected values here are derived from the actual crypto library.

TEST(Thorchain, ThorchainGetAddress) {
  HDNode node = {
      0,
      0,
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0x03, 0xb7, 0x32, 0x9f, 0x67, 0x8e, 0x0a, 0xc1, 0x21, 0x4b, 0x77,
       0x23, 0x57, 0x54, 0x66, 0x21, 0x9c, 0x77, 0xfe, 0xdb, 0xdd, 0x95,
       0x5c, 0x33, 0x29, 0x1a, 0x74, 0xf1, 0x8b, 0xf5, 0xc8, 0xa4, 0xe2},
      &secp256k1_info};
  char addr[46];
  ASSERT_TRUE(tendermint_getAddress(&node, "thor", addr));
  EXPECT_EQ(std::string("thor1am058pdux3hyulcmfgj4m3hhrlfn8nzmpq9u6l"), addr);
}

// Shared fixtures
static const HDNode kSignNode = {
    0,
    0,
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0x04, 0xde, 0xc0, 0xcc, 0x01, 0x3c, 0xd8, 0xab, 0x70, 0x87, 0xca,
     0x14, 0x96, 0x0b, 0x76, 0x8c, 0x3d, 0x83, 0x45, 0x24, 0x48, 0xaa,
     0x00, 0x64, 0xda, 0xe6, 0xfb, 0x04, 0xb5, 0xd9, 0x34, 0x76},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    &secp256k1_info};

static const ThorchainSignTx kSignTx = {
    5,    {0x80000000 | 44, 0x80000000 | 931, 0x80000000, 0, 0},
    true, 0,
    true, "thorchain",
    true, 5000,
    true, 200000,
    true, "",
    true, 0,
    true, 1};

// Known-valid thor1 address (same decoded payload as previously broken
// "thor18vhdczjut44gpsy804crfhnd5nq003nz0nf20v" which had bad bech32 checksum)
static const char* kToAddr = "thor1am058pdux3hyulcmfgj4m3hhrlfn8nzmpq9u6l";

TEST(Thorchain, ThorchainSignTx) {
  HDNode node = kSignNode;
  hdnode_fill_public_key(&node);

  ASSERT_TRUE(thorchain_signTxInit(&node, &kSignTx));
  ASSERT_TRUE(thorchain_signTxUpdateMsgSend(100000, kToAddr, "rune"));

  uint8_t public_key[33];
  uint8_t signature[64];
  ASSERT_TRUE(thorchain_signTxFinalize(public_key, signature));
}

// Empty denom must produce identical output to explicit "rune"
TEST(Thorchain, ThorchainSignTxDefaultDenom) {
  HDNode node = kSignNode;
  hdnode_fill_public_key(&node);

  ASSERT_TRUE(thorchain_signTxInit(&node, &kSignTx));
  ASSERT_TRUE(thorchain_signTxUpdateMsgSend(100000, kToAddr, ""));

  uint8_t public_key[33];
  uint8_t signature[64];
  ASSERT_TRUE(thorchain_signTxFinalize(public_key, signature));

  // Default empty denom must produce the same signature as explicit "rune"
  uint8_t public_key2[33];
  uint8_t sig_rune[64];
  HDNode node2 = kSignNode;
  hdnode_fill_public_key(&node2);
  ASSERT_TRUE(thorchain_signTxInit(&node2, &kSignTx));
  ASSERT_TRUE(thorchain_signTxUpdateMsgSend(100000, kToAddr, "rune"));
  ASSERT_TRUE(thorchain_signTxFinalize(public_key2, sig_rune));
  EXPECT_EQ(0, memcmp(signature, sig_rune, 64));
}

TEST(Thorchain, ThorchainSignTxTCY) {
  HDNode node = kSignNode;
  hdnode_fill_public_key(&node);

  ASSERT_TRUE(thorchain_signTxInit(&node, &kSignTx));
  ASSERT_TRUE(thorchain_signTxUpdateMsgSend(100000, kToAddr, "tcy"));

  uint8_t public_key[33];
  uint8_t signature[64];
  ASSERT_TRUE(thorchain_signTxFinalize(public_key, signature));
}

TEST(Thorchain, ThorchainSignTxRujira) {
  HDNode node = kSignNode;
  hdnode_fill_public_key(&node);

  ASSERT_TRUE(thorchain_signTxInit(&node, &kSignTx));
  ASSERT_TRUE(thorchain_signTxUpdateMsgSend(100000, kToAddr, "rujira"));

  uint8_t public_key[33];
  uint8_t signature[64];
  ASSERT_TRUE(thorchain_signTxFinalize(public_key, signature));
}

// Denom validation: only [a-z0-9./\-] is allowed; anything else is rejected
TEST(Thorchain, ThorchainDenomValidation) {
  EXPECT_TRUE(thorchain_isValidDenom("rune"));
  EXPECT_TRUE(thorchain_isValidDenom("tcy"));
  EXPECT_TRUE(thorchain_isValidDenom("rujira"));
  EXPECT_TRUE(thorchain_isValidDenom("eth.eth"));
  EXPECT_TRUE(thorchain_isValidDenom("btc/btc"));
  EXPECT_TRUE(thorchain_isValidDenom("cross-chain"));

  EXPECT_FALSE(thorchain_isValidDenom(""));        // empty → caller uses "rune"
  EXPECT_FALSE(thorchain_isValidDenom("RUNE"));    // uppercase rejected
  EXPECT_FALSE(thorchain_isValidDenom("rune\""));  // quote injection
  EXPECT_FALSE(thorchain_isValidDenom("rune\\n"));  // backslash injection
  EXPECT_FALSE(thorchain_isValidDenom(" rune"));    // leading space
  EXPECT_FALSE(thorchain_isValidDenom("ru ne"));    // embedded space
}

// Invalid denom must cause thorchain_signTxUpdateMsgSend to return false
TEST(Thorchain, ThorchainSignTxInvalidDenom) {
  HDNode node = kSignNode;
  hdnode_fill_public_key(&node);

  ASSERT_TRUE(thorchain_signTxInit(&node, &kSignTx));
  // Quote-injection attempt must be rejected at the signing layer
  EXPECT_FALSE(thorchain_signTxUpdateMsgSend(100000, kToAddr,
                                             "rune\",\"from_address\":\"evil"));
  thorchain_signAbort();
}
