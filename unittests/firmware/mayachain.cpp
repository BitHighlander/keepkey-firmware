extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/mayachain.h"
#include "keepkey/firmware/tendermint.h"
#include "trezor/crypto/secp256k1.h"
}

#include "gtest/gtest.h"
#include <cstring>

TEST(Mayachain, MayachainGetAddress) {
  HDNode node = {
      0,
      0,
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0x03, 0x15, 0x19, 0x71, 0x3b, 0x8b, 0x42, 0xbd, 0xc3, 0x67, 0x11,
       0x2d, 0x33, 0x13, 0x2c, 0xf1, 0x4c, 0xed, 0xf9, 0x28, 0xac, 0x57,
       0x71, 0xd4, 0x44, 0xba, 0x45, 0x9b, 0x94, 0x97, 0x11, 0x7b, 0xa3},
      &secp256k1_info};
  char addr[46];
  ASSERT_TRUE(tendermint_getAddress(&node, "maya", addr));
  EXPECT_EQ(std::string("maya1ls33ayg26kmltw7jjy55p32ghjna09zp7z4etj"), addr);
}

TEST(Mayachain, MayachainSignTx) {
  HDNode node = {
      0,
      0,
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0xb9, 0x9a, 0x39, 0x3a, 0x5a, 0x53, 0x0d, 0x90, 0xef, 0x6e, 0x46,
       0x4e, 0x8e, 0x2f, 0x2b, 0x8b, 0x5c, 0x64, 0xa7, 0x97, 0x29, 0xcd,
       0x60, 0x3b, 0x1f, 0xba, 0x33, 0x81, 0x7d, 0x1a, 0x75, 0xa1},
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      &secp256k1_info};
  hdnode_fill_public_key(&node);

  const MayachainSignTx msg = {
      5,    {0x80000000 | 44, 0x80000000 | 931, 0x80000000, 0, 0},  // address_n
      true, 6359,                    // account_number
      true, "mayachain-mainnet-v1",  // chain_id
      true, 3000,                    // fee_amount
      true, 200000,                  // gas
      true, "",                      // memo
      true, 19,                      // sequence
      true, 1                        // msg_count
  };
  ASSERT_TRUE(mayachain_signTxInit(&node, &msg));

  ASSERT_TRUE(mayachain_signTxUpdateMsgSend(
      100, "maya1g9el7lzjwh9yun2c4jjzhy09j98vkhfxfqkl5k", "cacao"));

  uint8_t public_key[33];
  uint8_t signature[64];

  ASSERT_TRUE(mayachain_signTxFinalize(public_key, signature));
}
