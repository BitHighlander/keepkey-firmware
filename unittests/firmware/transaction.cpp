// gtest first: confirm_sm.h defines an isprint() macro that collides with the
// standard library declaration when C++ headers are included afterwards.
#include "gtest/gtest.h"

#include <cstring>
#include <vector>

extern "C" {
#include "keepkey/board/confirm_sm.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/transaction.h"
}

// confirm() auto-accept driver, defined in thorchain.cpp (same binary).
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

TEST(Transaction, TaprootInputWeightIncludesWitness) {
  CoinType coin = CoinType_init_zero;
  TxInputType input = TxInputType_init_zero;
  input.script_type = InputScriptType_SPENDTAPROOT;

  // 41 non-witness bytes * 4 plus a one-item witness containing the fixed
  // 64-byte SIGHASH_DEFAULT Schnorr signature.
  ASSERT_EQ(230U, tx_input_weight(&coin, &input));
}

TEST(Transaction, UnsupportedOmniDisclosesTheCompleteRawPayload) {
  std::vector<uint8_t> payload(220, 0x00);
  memcpy(payload.data(), "omni", 4);
  payload[7] = 1;  // unsupported transaction type, not Simple Send (type 0)

  size_t pages = 0;
  size_t offset = 0;
  while (offset < payload.size()) {
    char page[BODY_CHAR_MAX];
    const size_t take = confirm_bytes_format_page(
        payload.data() + offset, payload.size() - offset, page, sizeof(page));
    ASSERT_GT(take, 0u);
    offset += take;
    pages++;
  }
  ASSERT_GT(pages, 1u)
      << "fixture must distinguish raw pagination from one generic warning";

  ASSERT_TRUE(kkconfirm_preload(static_cast<int>(pages), 0));
  EXPECT_TRUE(confirm_omni(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           "Confirm OMNI", payload.data(), payload.size()));
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(Transaction, MultisigQuorumRejectsUnsatisfiableScripts) {
  MultisigRedeemScriptType multisig = MultisigRedeemScriptType_init_zero;
  CoinType coin = CoinType_init_zero;
  uint8_t output[512] = {0};
  uint8_t hash[32] = {0};

  multisig.has_m = true;
  multisig.m = 2;
  multisig.pubkeys_count = 1;
  EXPECT_FALSE(transaction_multisig_quorum_is_valid(&multisig));
  EXPECT_EQ(compile_script_multisig(&coin, &multisig, output), 0U);
  EXPECT_EQ(compile_script_multisig_hash(&coin, &multisig, hash), 0U);

  multisig.m = 0;
  EXPECT_FALSE(transaction_multisig_quorum_is_valid(&multisig));
  multisig.m = 16;
  multisig.pubkeys_count = 16;
  EXPECT_FALSE(transaction_multisig_quorum_is_valid(&multisig));

  multisig.m = 2;
  multisig.pubkeys_count = 3;
  EXPECT_TRUE(transaction_multisig_quorum_is_valid(&multisig));
}
