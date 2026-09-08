extern "C" {
#include "keepkey/firmware/eos.h"
#include "keepkey/firmware/eos-contracts/eosio.system.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/storage.h"
#include "messages-eos.pb.h"

void setup(void);
}

#include "gtest/gtest.h"

#include <cstring>
#include <string>

bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

TEST(EOS, UnknownActionsRequireAdvancedMode) {
  EXPECT_FALSE(eos_unknownActionPolicyAllows(false));
  EXPECT_TRUE(eos_unknownActionPolicyAllows(true));
}

TEST(EOS, NewAccountCannotDowngradeToUnknownAction) {
  EosActionCommon common = {};
  common.has_account = true;
  common.account = EOS_eosio;
  common.has_name = true;
  common.name = EOS_NewAccount;
  EXPECT_TRUE(eos_isSupportedAction(&common));

  common.account = 0x1111111111111111ULL;
  EXPECT_FALSE(eos_isSupportedAction(&common));
}

TEST(EOS, FormatNameVec) {
  struct {
    uint64_t value;
    const char* name;
    bool ret;
  } vec[] = {
      {0x5530ea0000000000, "eosio", true},
      {0x0000000000ea3055, nullptr, true},
      {0x5530ea031ec65520, "eosio.system", true},
      {0xb68d3cbb3e000000, "quantity", true},
      {0x9ab864229a9e4000, "newaccount", true},
      {EOS_Transfer, "transfer", true},
      {0xcdcd3c2d57000000, "transfer", true},
      {0xd4d2a8a986ca8fc0, "undelegatebw", true},
      {0xc2b263b800000000, "setabi", true},
      {0xa726ab8000000000, "owner", true},
      {EOS_Owner, "owner", true},
      {0x3232eda800000000, "active", true},
      {EOS_Active, "active", true},
      {0x5530002eea526920, "eos..freedom", true},
      {0x5530412eea526920, "eos42freedom", true},
      {0x0, "", true},
  };

  for (const auto& v : vec) {
    char str[EOS_NAME_STR_SIZE];
    ASSERT_EQ(v.ret, eos_formatName(v.value, str));
    if (v.name) ASSERT_EQ(v.name, std::string(str));
  }
}

TEST(EOS, FormatAssetVec) {
  struct {
    int64_t amount;
    uint64_t symbol;
    std::string expected;
    bool ret;
  } vec[] = {
      {7654321L, 0x000000534f4504L, "765.4321 EOS", true},
      {42L, 0x004e45584f4600L, "42 FOXEN", true},
      {42L, 0x004e45584f4601L, "4.2 FOXEN", true},
      {42L, 0x004e45584f4602L, "0.42 FOXEN", true},
      {42L, 0x004e45584f4603L, "0.042 FOXEN", true},
      {42L, 0x004e45584f4604L, "0.0042 FOXEN", true},
      {42L, 0x004e45584f4605L, "0.00042 FOXEN", true},
      {42L, 0x004e45584f4606L, "0.000042 FOXEN", true},
      {42L, 0x004e45584f4607L, "0.0000042 FOXEN", true},
      {42L, 0x004e45584f4608L, "0.00000042 FOXEN", true},
      {42L, 0x004e45584f4609L, "0.000000042 FOXEN", true},
      {-10L, 0x00000053595305L, "-0.00010 SYS", true},
      {INT64_MIN, 0x00000053595303L, "-9223372036854775.808 SYS", true},
      {20000L, 0x000000534f4504L, "2.0000 EOS", true},
      {200000L, 0x000000534f4504L, "20.0000 EOS", true},
      {2000000L, 0x000000534f4504L, "200.0000 EOS", true},
      {20000000L, 0x000000534f4504L, "2000.0000 EOS", true},
      {200000000L, 0x000000534f4504L, "20000.0000 EOS", true},
      {2000000000L, 0x000000534f4504L, "200000.0000 EOS", true},
      {20000000000L, 0x000000534f4504L, "2000000.0000 EOS", true},
      {200000000000L, 0x000000534f4504L, "20000000.0000 EOS", true},
      {2000000000000L, 0x000000534f4504L, "200000000.0000 EOS", true},
      {20000000000000L, 0x000000534f4504L, "2000000000.0000 EOS", true},
      {10000L, 0x000000534f4504L, "1.0000 EOS", true},
      {100000L, 0x000000534f4504L, "10.0000 EOS", true},
      {1000000L, 0x000000534f4504L, "100.0000 EOS", true},
      {10000000L, 0x000000534f4504L, "1000.0000 EOS", true},
      {100000000L, 0x000000534f4504L, "10000.0000 EOS", true},
      {1000000000L, 0x000000534f4504L, "100000.0000 EOS", true},
      {10000000000L, 0x000000534f4504L, "1000000.0000 EOS", true},
      {100000000000L, 0x000000534f4504L, "10000000.0000 EOS", true},
      {1000000000000L, 0x000000534f4504L, "100000000.0000 EOS", true},
      {10000000000000L, 0x000000534f4504L, "1000000000.0000 EOS", true},
  };

  for (const auto& v : vec) {
    char str[EOS_ASSET_STR_SIZE];
    EosAsset asset;
    asset.has_amount = true;
    asset.amount = v.amount;
    asset.has_symbol = true;
    asset.symbol = v.symbol;
    EXPECT_EQ(v.ret, eos_formatAsset(&asset, str));
    EXPECT_EQ(v.expected, str);
  }
}

TEST(EOS, PublicKeyToWIF) {
  uint8_t public_key[33];
  memset(public_key, 0, sizeof(public_key));
  char pubkey[64];
  memset(pubkey, 0, sizeof(pubkey));
  ASSERT_FALSE(eos_publicKeyToWif(public_key, (EosPublicKeyKind)42, pubkey,
                                  sizeof(pubkey)));

  ASSERT_TRUE(eos_publicKeyToWif(public_key, EosPublicKeyKind_EOS_K1, pubkey,
                                 sizeof(pubkey)));
  ASSERT_EQ(pubkey,
            std::string("EOS_K1_1111111111111111111111111111111114T1Anm"));
}

// An interior NUL in the symbol used to be accepted and written into the
// display string, so "%s" showed only the prefix while eos_compileAsset
// signed the full 8 bytes. Canonical symbols are A-Z with trailing zero
// padding only; a letter after a zero must be refused.
TEST(EOS, FormatAssetRejectsNonCanonicalSymbol) {
  EosAsset asset;
  asset.has_amount = true;
  asset.amount = 10000;
  asset.has_symbol = true;
  // precision 4, then bytes 'A', 0, 'X', 'X', 'X', 0, 0
  asset.symbol = 0x0000585858004104ULL;
  char str[EOS_ASSET_STR_SIZE];
  EXPECT_FALSE(eos_formatAsset(&asset, str));
  EXPECT_EQ(0, str[0]);

  // Control: the same letters in canonical order are fine.
  asset.symbol = 0x0000000058585804ULL;
  EXPECT_TRUE(eos_formatAsset(&asset, str));
  EXPECT_EQ("1.0000 XXX", std::string(str));
}

// EOSIO caps precision at 18. Larger values got no decimal point and no error,
// so the amount was displayed as a bare integer while the precision byte was
// signed.
TEST(EOS, FormatAssetRejectsPrecisionAbove18) {
  EosAsset asset;
  asset.has_amount = true;
  asset.amount = 10000;
  asset.has_symbol = true;
  char str[EOS_ASSET_STR_SIZE];

  asset.symbol = 0x000000534f4500ULL | 19;
  EXPECT_FALSE(eos_formatAsset(&asset, str));
  asset.symbol = 0x000000534f4500ULL | 200;
  EXPECT_FALSE(eos_formatAsset(&asset, str));

  asset.symbol = 0x000000534f4500ULL | 18;
  EXPECT_TRUE(eos_formatAsset(&asset, str));
  EXPECT_EQ("0.000000000000010000 EOS", std::string(str));
}

// delegatebw with transfer=true permanently hands the staked tokens to the
// receiver. That must get its own explicit screen, and the verb must not read
// as a mere delegation; transfer=false stays a single "Delegate" screen.
TEST(EOS, DelegateWithTransferDisclosesOwnershipTransfer) {
  EosActionCommon common;
  memset(&common, 0, sizeof(common));
  common.has_account = true;
  common.account = EOS_eosio;
  common.has_name = true;
  common.name = EOS_DelegateBW;
  common.authorization_count = 1;

  EosActionDelegate action;
  memset(&action, 0, sizeof(action));
  action.has_sender = true;
  action.sender = 0x5530ea0000000000ULL;  // eosio
  action.has_receiver = true;
  action.receiver = 0x5530ea0000000000ULL;
  action.has_cpu_quantity = true;
  action.cpu_quantity.has_amount = true;
  action.cpu_quantity.amount = 10000;
  action.cpu_quantity.has_symbol = true;
  action.cpu_quantity.symbol = 0x000000534f4504ULL;
  action.net_quantity = action.cpu_quantity;
  action.has_net_quantity = true;

  // Signing is not initialised, so compileActionCommon fails AFTER the
  // screens; only the screen count matters here.
  action.has_transfer = true;
  action.transfer = true;
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  eos_compileActionDelegate(&common, &action);
  EXPECT_EQ(0, kkconfirm_drain());

  action.transfer = false;
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  eos_compileActionDelegate(&common, &action);
  EXPECT_EQ(0, kkconfirm_drain());
  eos_signingAbort();
}

// max_net_usage_words is hashed as a full 32-bit varuint but the budget screen
// formats it through a uint16 cast, so 0x10000 showed as 0. It must be bounded
// like max_cpu_usage_ms and ref_block_num.
TEST(EOS, SignTxRejectsNetUsageWordsOverflow) {
  if (storage_getLocation() == FLASH_INVALID) {
    setup();
    storage_init();
  }
  session_clear(true);
  storage_setMnemonic("all all all all all all all all all all all all");

  EosSignTx msg;
  memset(&msg, 0, sizeof(msg));
  msg.has_chain_id = true;
  msg.chain_id.size = 32;
  msg.has_header = true;
  msg.has_num_actions = true;
  msg.num_actions = 1;

  msg.header.max_net_usage_words = 0x10000;
  fsm_msgEosSignTx(&msg);
  EXPECT_FALSE(eos_signingIsInited());

  msg.header.max_net_usage_words = UINT16_MAX;
  fsm_msgEosSignTx(&msg);
  EXPECT_TRUE(eos_signingIsInited());
  eos_signingAbort();
}
