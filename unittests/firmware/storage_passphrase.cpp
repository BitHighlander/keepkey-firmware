#include "gtest/gtest.h"
#include "test_board.h"

#include <cstring>

extern "C" {
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/signing.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/transport/interface.h"
#include "keepkey/emulator/setup.h"
#include "trezor/crypto/bip39.h"
#include "trezor/crypto/curves.h"
#include "trezor/crypto/memzero.h"
}


namespace {
const char kMnemonic[] = "all all all all all all all all all all all all";
const char kHidden[] = "hidden wallet";

class PassphraseTransition : public ::testing::Test {
 protected:
  void SetUp() override {
    static bool initialized = false;
    if (!initialized) {
      setup();
      kk_test_board_init();
      storage_init();
      initialized = true;
    }
    LoadDevice load = {};
    load.has_mnemonic = true;
    std::strcpy(load.mnemonic, kMnemonic);
    storage_loadDevice(&load);
    storage_commit();
  }

  void TearDown() override {
    setup_abort();
    session_clear(true);
  }

  void ExpectWallet(const char* passphrase, const HDNode& actual) {
    uint8_t seed[64] = {};
    HDNode expected = {};
    mnemonic_to_seed(kMnemonic, passphrase, seed, nullptr);
    ASSERT_EQ(1,
              hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &expected));
    EXPECT_EQ(0, std::memcmp(actual.private_key, expected.private_key, 32));
    EXPECT_EQ(0, std::memcmp(actual.chain_code, expected.chain_code, 32));
    memzero(seed, sizeof(seed));
    memzero(&expected, sizeof(expected));
  }
};

TEST_F(PassphraseTransition, DisableSelectsPlainWallet) {
  storage_setPassphraseProtected(true);
  session_cachePassphrase(kHidden);
  HDNode node = {};
  ASSERT_TRUE(storage_getRootNode(SECP256K1_NAME, true, &node));
  ExpectWallet(kHidden, node);

  storage_setPassphraseProtected(false);
  EXPECT_FALSE(session_isPassphraseCached());
  ASSERT_TRUE(storage_getRootNode(SECP256K1_NAME, true, &node));
  ExpectWallet("", node);
  memzero(&node, sizeof(node));
}

TEST_F(PassphraseTransition, EnableSelectsNewlyConfirmedWallet) {
  HDNode node = {};
  ASSERT_TRUE(storage_getRootNode(SECP256K1_NAME, true, &node));
  ExpectWallet("", node);

  storage_setPassphraseProtected(true);
  EXPECT_FALSE(session_isPassphraseCached());
  session_cachePassphrase(kHidden);
  ASSERT_TRUE(storage_getRootNode(SECP256K1_NAME, true, &node));
  ExpectWallet(kHidden, node);
  memzero(&node, sizeof(node));
}

TEST_F(PassphraseTransition, UnchangedSettingPreservesConfirmedPassphrase) {
  storage_setPassphraseProtected(true);
  session_cachePassphrase(kHidden);
  HDNode node = {};
  ASSERT_TRUE(storage_getRootNode(SECP256K1_NAME, true, &node));
  storage_setPassphraseProtected(true);
  EXPECT_TRUE(session_isPassphraseCached());
  ASSERT_TRUE(storage_getRootNode(SECP256K1_NAME, true, &node));
  ExpectWallet(kHidden, node);
  memzero(&node, sizeof(node));
}
TEST_F(PassphraseTransition, SettingChangePreservesPinAuthorization) {
  storage_setPin("1234");
  ASSERT_TRUE(session_isPinCached());
  storage_setPassphraseProtected(true);
  EXPECT_TRUE(session_isPinCached());
  storage_setPassphraseProtected(false);
  EXPECT_TRUE(session_isPinCached());
}

TEST_F(PassphraseTransition, SettingChangePreservesStagedSetup) {
  ASSERT_TRUE(setup_stage(true, "english", "staged label", 0, 0, false));
  setup_arm(SETUP_RESET);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  storage_setPassphraseProtected(true);
  EXPECT_TRUE(setup_isArmedAs(SETUP_RESET));
}

TEST_F(PassphraseTransition, StagingIsInertAndForeignCommitAborts) {
  storage_setLabel("original");
  storage_commit();
  ASSERT_FALSE(storage_getPassphraseProtected());
  ASSERT_FALSE(storage_hasPin());

  ASSERT_TRUE(setup_stage(true, "english", "pending", 0, 37, false));
  ASSERT_TRUE(setup_stagePin(false));
  setup_arm(SETUP_RESET);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  EXPECT_STREQ("original", storage_getLabel());
  EXPECT_FALSE(storage_getPassphraseProtected());
  EXPECT_FALSE(storage_hasPin());

  storage_commit();

  EXPECT_FALSE(setup_isArmed());
  EXPECT_STREQ("original", storage_getLabel());
  EXPECT_FALSE(storage_getPassphraseProtected());
  EXPECT_FALSE(storage_hasPin());
  EXPECT_FALSE(setup_stagePin(false));
  setup_arm(SETUP_RESET);
  EXPECT_FALSE(setup_isArmed());
}

}  // namespace

TEST_F(PassphraseTransition,
       InitializeRetainsPinButAbortsSigningAndPassphrase) {
  fsm_init();
  storage_setPin("1234");
  storage_setPassphraseProtected(true);
  session_cachePassphrase(kHidden);
  ASSERT_TRUE(session_isPinCached());
  ASSERT_TRUE(session_isPassphraseCached());
  SignTx start = {};
  start.inputs_count = start.outputs_count = 1;
  HDNode root = {};
  signing_init(&start, coinByName("Bitcoin"), &root);
  ASSERT_TRUE(signing_is_active());
  fsm_msgInitialize(nullptr);
  EXPECT_FALSE(signing_is_active());
  EXPECT_TRUE(session_isPinCached());
  EXPECT_FALSE(session_isPassphraseCached());
}

extern "C" {
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/passphrase_sm.h"
}

// The confirmation shows a typed passphrase escaped, and PASSPHRASE_NONE_TEXT
// when there is none. A host must not be able to send a passphrase that draws
// the "none" screen: it would open a different wallet under that label. The
// old wording, "(empty)", could simply be typed.
TEST(StoragePassphrase, NoPassphraseTextCannotBeTyped) {
  // The escape never emits a raw space, whatever the byte.
  for (int value = 0; value < 256; value++) {
    const uint8_t byte = static_cast<uint8_t>(value);
    char escaped[8];
    ASSERT_TRUE(confirm_bytes_escape(&byte, 1, escaped, sizeof(escaped)));
    EXPECT_EQ(nullptr, strchr(escaped, ' ')) << value;
  }
  // The "none" text has one, so nothing typed can equal it, itself included.
  ASSERT_NE(nullptr, strchr(PASSPHRASE_NONE_TEXT, ' '));
  char escaped[4 * sizeof(PASSPHRASE_NONE_TEXT)];
  ASSERT_TRUE(confirm_bytes_escape(
      reinterpret_cast<const uint8_t*>(PASSPHRASE_NONE_TEXT),
      strlen(PASSPHRASE_NONE_TEXT), escaped, sizeof(escaped)));
  EXPECT_STRNE(PASSPHRASE_NONE_TEXT, escaped);
}
