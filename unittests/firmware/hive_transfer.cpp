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

template <typename Request, typename Response, typename Sign>
static void check_chain_id_contract(Request request, Sign sign) {
  // Omission is the documented mainnet default. Explicit malformed bytes
  // must never silently select that default, including an empty bytes field.
  Response baseline = {};
  sign(request, baseline);
  ASSERT_TRUE(baseline.has_signature);
  ASSERT_TRUE(baseline.has_serialized_tx);
  request.has_chain_id = true;
  memset(request.chain_id.bytes, 0xa5, sizeof(request.chain_id.bytes));
  for (size_t size = 0; size < HIVE_CHAIN_ID_LEN; ++size) {
    SCOPED_TRACE(size);
    request.chain_id.size = size;
    Response response = {};
    sign(request, response);
    EXPECT_FALSE(response.has_signature);
    EXPECT_FALSE(response.has_serialized_tx);
  }

  request.chain_id.size = HIVE_CHAIN_ID_LEN;
  const uint8_t mainnet[32] = {0xbe, 0xea, 0xb0, 0xde};
  memcpy(request.chain_id.bytes, mainnet, sizeof(mainnet));
  Response explicit_mainnet = {};
  sign(request, explicit_mainnet);
  ASSERT_TRUE(explicit_mainnet.has_signature);
  EXPECT_EQ(baseline.signature.size, explicit_mainnet.signature.size);
  EXPECT_EQ(0,
            memcmp(baseline.signature.bytes, explicit_mainnet.signature.bytes,
                   baseline.signature.size));

  // Preserve support for exact-length custom domains; their signatures must
  // differ even though the serialized transaction remains identical.
  request.chain_id.bytes[0] ^= 1;
  Response custom = {};
  sign(request, custom);
  ASSERT_TRUE(custom.has_signature);
  ASSERT_EQ(baseline.serialized_tx.size, custom.serialized_tx.size);
  EXPECT_EQ(0, memcmp(baseline.serialized_tx.bytes, custom.serialized_tx.bytes,
                      baseline.serialized_tx.size));
  EXPECT_NE(0, memcmp(baseline.signature.bytes, custom.signature.bytes,
                      baseline.signature.size));
}

TEST(Hive, AllSigningOperationsRejectMalformedExplicitChainIds) {
  HDNode node = {};
  const uint8_t seed[32] = {1};
  ASSERT_EQ(1, hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &node));
  hdnode_fill_public_key(&node);
  check_chain_id_contract<HiveSignTx, HiveSignedTx>(
      transfer_request(), [&](const HiveSignTx& msg, HiveSignedTx& response) {
        hive_signTx(&node, &msg, &response);
      });

  HiveSignAccountCreate create = {};
  create.has_creator = create.has_new_account_name = true;
  strcpy(create.creator, "alice");
  strcpy(create.new_account_name, "bob");
  create.has_ref_block_num = create.has_ref_block_prefix =
      create.has_expiration = true;
  create.ref_block_num = 1;
  create.ref_block_prefix = 2;
  create.expiration = 3;
  check_chain_id_contract<HiveSignAccountCreate, HiveSignedAccountCreate>(
      create,
      [&](const HiveSignAccountCreate& msg, HiveSignedAccountCreate& response) {
        hive_signAccountCreate(&node, &msg, node.public_key, node.public_key,
                               node.public_key, node.public_key, &response);
      });

  HiveSignAccountUpdate update = {};
  update.has_account = true;
  strcpy(update.account, "alice");
  update.has_ref_block_num = update.has_ref_block_prefix =
      update.has_expiration = true;
  update.ref_block_num = 1;
  update.ref_block_prefix = 2;
  update.expiration = 3;
  check_chain_id_contract<HiveSignAccountUpdate, HiveSignedAccountUpdate>(
      update,
      [&](const HiveSignAccountUpdate& msg, HiveSignedAccountUpdate& response) {
        hive_signAccountUpdate(&node, &msg, node.public_key, node.public_key,
                               node.public_key, node.public_key, &response);
      });
}

TEST(Hive, TransferRejectsInvalidAmountAndAccountLabels) {
  HDNode node = {};
  const uint8_t seed[32] = {1};
  ASSERT_EQ(1, hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &node));
  for (uint64_t amount : {uint64_t(0), uint64_t(INT64_MAX) + 1, UINT64_MAX}) {
    HiveSignTx msg = transfer_request();
    msg.amount = amount;
    HiveSignedTx response = {};
    hive_signTx(&node, &msg, &response);
    EXPECT_FALSE(response.has_signature) << amount;
    EXPECT_FALSE(response.has_serialized_tx);
  }
  for (const char* name : {"", "ab", "Alice", "alice\nbob", "alice bob",
                           "@alice", "-alice", "alice-", "ali_ce", ".alice",
                           "alice.", "alice..bob", "a.bob", "alice.1bob"}) {
    for (bool sender : {false, true}) {
      HiveSignTx msg = transfer_request();
      strcpy(sender ? msg.from : msg.to, name);
      HiveSignedTx response = {};
      hive_signTx(&node, &msg, &response);
      EXPECT_FALSE(response.has_signature) << name;
      EXPECT_FALSE(response.has_serialized_tx);
    }
  }
  for (const char* name :
       {"abc", "alice-bob", "alice.bob", "abcdefghijklmnop"}) {
    HiveSignTx msg = transfer_request();
    strcpy(msg.from, name);
    strcpy(msg.to, name);
    msg.amount = INT64_MAX;
    msg.has_memo = true;
    memset(msg.memo, 'm', HIVE_MAX_MEMO_LEN);
    msg.memo[HIVE_MAX_MEMO_LEN] = 0;
    HiveSignedTx response = {};
    hive_signTx(&node, &msg, &response);
    ASSERT_TRUE(response.has_signature) << name;
    // Header12 + two length-prefixed accounts + asset16 + memo varint2 +
    // memo440 + extensions1. Proves the maximum payload is not truncated.
    EXPECT_EQ(473u + 2u * strlen(name), response.serialized_tx.size);
    EXPECT_EQ(0, response.serialized_tx.bytes[response.serialized_tx.size - 1]);
  }
}
