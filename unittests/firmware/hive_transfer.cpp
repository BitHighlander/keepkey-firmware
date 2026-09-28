extern "C" {
#include "keepkey/firmware/hive.h"
#include "trezor/crypto/curves.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"
}

#include "gtest/gtest.h"
#include <cstring>
#include <vector>

static HiveSignTx transfer_request() {
  HiveSignTx msg = {};
  msg.has_from = msg.has_to = msg.has_amount = true;
  strcpy(msg.from, "alice");
  strcpy(msg.to, "bob");
  msg.amount = 1000;
  msg.has_ref_block_num = msg.has_ref_block_prefix = msg.has_expiration = true;
  msg.ref_block_num = 1;
  msg.ref_block_prefix = 2;
  msg.expiration = 3;
  return msg;
}

TEST(Hive, TransferAssetShownIsAssetSigned) {
  HDNode node = {};
  const uint8_t seed[32] = {1};
  ASSERT_EQ(1, hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &node));
  hdnode_fill_public_key(&node);
  for (const char* symbol : {"HIVE", "STEEM", "HBD", "SBD"}) {
    SCOPED_TRACE(symbol);
    HiveSignTx msg = transfer_request();
    msg.has_asset_symbol = true;
    strcpy(msg.asset_symbol, symbol);
    const bool hive =
        strcmp(symbol, "HIVE") == 0 || strcmp(symbol, "STEEM") == 0;
    const char *wire, *display;
    uint8_t precision = 0;
    ASSERT_TRUE(hive_transferAsset(&msg, &wire, &display, &precision));
    EXPECT_STREQ(hive ? "HIVE" : "HBD", display);
    EXPECT_STREQ(hive ? "STEEM" : "SBD", wire);
    EXPECT_EQ(3, precision);

    // Independent bytes, including empty memo/extensions; do not use the
    // firmware serializer or response as the signature oracle.
    std::vector<uint8_t> expected = {
        1,   0,   2, 0,   0,   0,   3,    0, 0, 0, 1, 2, 5, 'a', 'l', 'i',
        'c', 'e', 3, 'b', 'o', 'b', 0xe8, 3, 0, 0, 0, 0, 0, 0,   3};
    const char* signed_symbol = hive ? "STEEM" : "SBD";
    for (size_t i = 0; i < 7; i++)
      expected.push_back(i < strlen(signed_symbol) ? signed_symbol[i] : 0);
    expected.push_back(0);
    expected.push_back(0);
    HiveSignedTx response = {};
    hive_signTx(&node, &msg, &response);
    ASSERT_TRUE(response.has_signature);
    ASSERT_TRUE(response.has_serialized_tx);
    ASSERT_EQ(expected.size(), response.serialized_tx.size);
    EXPECT_EQ(0, memcmp(expected.data(), response.serialized_tx.bytes,
                        expected.size()));
    std::vector<uint8_t> preimage = {0xbe, 0xea, 0xb0, 0xde};
    preimage.resize(32, 0);
    preimage.insert(preimage.end(), expected.begin(), expected.end());
    uint8_t digest[32];
    sha256_Raw(preimage.data(), preimage.size(), digest);
    EXPECT_EQ(0, ecdsa_verify_digest(&secp256k1, node.public_key,
                                     response.signature.bytes + 1, digest));
  }
}

TEST(Hive, TransferRejectsUnsupportedAssetsAndUntruncatedPrecision) {
  HDNode node = {};
  const uint8_t seed[32] = {1};
  ASSERT_EQ(1, hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &node));
  for (const char* symbol : {"", "HIVEX", "VESTS", "hive"}) {
    HiveSignTx msg = transfer_request();
    msg.has_asset_symbol = true;
    strcpy(msg.asset_symbol, symbol);
    HiveSignedTx response = {};
    hive_signTx(&node, &msg, &response);
    EXPECT_FALSE(response.has_signature);
    EXPECT_FALSE(response.has_serialized_tx);
  }
  for (uint32_t decimals : {0u, 2u, 4u, 18u, 259u, UINT32_MAX}) {
    HiveSignTx msg = transfer_request();
    msg.has_decimals = true;
    msg.decimals = decimals;
    HiveSignedTx response = {};
    hive_signTx(&node, &msg, &response);
    EXPECT_FALSE(response.has_signature);
    EXPECT_FALSE(response.has_serialized_tx);
  }
}
