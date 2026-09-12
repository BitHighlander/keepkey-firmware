#include "gtest/gtest.h"
#include <cstring>
extern "C" {
#include "trezor/crypto/sha2.h"
#include "keepkey/firmware/txin_check.h"
#include "keepkey/firmware/signing.h"
}

TEST(InputHistory, OutputsRetainTheSameInputDigest) {
  txin_dgst_initialize();
  const uint8_t input[] = {1, 2, 3};
  char amount[AMT_STR_LEN] = "0.0038 BTC";
  char address[ADDR_STR_LEN] = "recipient";
  txin_dgst_addto(input, sizeof(input));
  txin_dgst_final();
  txin_dgst_save(amount, address);
  for (int i = 0; i < 3; ++i) {
    txin_dgst_final();
    EXPECT_FALSE(txin_dgst_compare(amount, address));
    txin_dgst_save(amount, address);
  }
  txin_dgst_initialize();
}

TEST(InputHistory, AbortResetsCurrentInputsButPreservesComparisonHistory) {
  txin_dgst_initialize();
  const uint8_t input[] = {1, 2, 3};
  char amount[AMT_STR_LEN] = "0.0038 BTC";
  char address[ADDR_STR_LEN] = "recipient";
  txin_dgst_addto(input, sizeof(input));
  txin_dgst_final();
  txin_dgst_save(amount, address);
  signing_abort();
  txin_dgst_addto(input, sizeof(input));
  txin_dgst_final();
  EXPECT_FALSE(txin_dgst_compare(amount, address));
  txin_dgst_reset_current();
  const uint8_t changed[] = {4, 5, 6};
  txin_dgst_addto(changed, sizeof(changed));
  txin_dgst_final();
  EXPECT_TRUE(txin_dgst_compare(amount, address));
  txin_dgst_initialize();
}
