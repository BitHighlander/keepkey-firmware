extern "C" {
#include "keepkey/board/memory.h"
#include "keepkey/board/layout.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/bip85.h"
#include "keepkey/firmware/signed_metadata.h"
#include "storage.h"
}
#include "gtest/gtest.h"
#include <cstring>
#include <algorithm>
#include <vector>

bool kkconfirm_preload(int, int);
int kkconfirm_drain(void);

class ReviewHandlers : public ::testing::Test {
 protected:
  std::vector<uint8_t> flash = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous;
  void SetUp() override {
    ASSERT_TRUE(kkconfirm_preload(0, 0));
    ASSERT_EQ(0, kkconfirm_drain());
    previous = emulator_flash_base;
    emulator_flash_base = flash.data();
    storage_init();
    LoadDevice load = {};
    load.has_mnemonic = true;
    strcpy(load.mnemonic, "all all all all all all all all all all all all");
    storage_loadDevice(&load);
    fsm_test_clearLastFailure();
  }
  void TearDown() override {
    fsm_abort_workflows();
    kkconfirm_drain();
#if !BITCOIN_ONLY
    signed_metadata_clear_signers();
#endif
    storage_wipe();
    storage_reset();
    emulator_flash_base = previous;
  }
};

TEST_F(ReviewHandlers, NewerWalletRefusesEveryMutationBeforeConsent) {
  char record[STORAGE_SECTOR_LEN] = {};
  memcpy(record, "stor", 4);
  record[44] = STORAGE_VERSION + 1;
  SessionState session = {};
  ConfigFlash shadow = {};
  ASSERT_EQ(SUS_TooNew, storage_fromFlash(&session, &shadow, record));
  std::fill(flash.begin(), flash.end(), 0xff);
  memcpy(flash.data() + 0x4000, record, sizeof(record));
  storage_init();
  ASSERT_TRUE(storage_isFirmwareTooOld());
  // A normal-band wallet newer than this build is refused with
  // UnexpectedMessage (CHECK_STORAGE_WRITABLE, pinned by
  // Fsm IncompatibleStorage.*); Failure_Other is reserved for bitcoin-only
  // locks (CHECK_NOT_BTC_ONLY_LOCKED).
  const auto unchanged = flash;
  ChangePin pin = {};
  ChangeWipeCode wipe_code = {};
  LoadDevice load = {};
  ResetDevice reset = {};
  ApplySettings settings = {};
  ApplyPolicies policies = {};
  RecoveryDevice recovery = {};
#define REFUSED(call)                                               \
  fsm_test_clearLastFailure();                                      \
  call;                                                             \
  EXPECT_EQ(FailureType_Failure_UnexpectedMessage,                  \
            fsm_test_lastFailureCode());                            \
  EXPECT_EQ(unchanged, flash);                                      \
  EXPECT_FALSE(setup_isArmed())
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  REFUSED(fsm_msgChangePin(&pin));
  REFUSED(fsm_msgChangeWipeCode(&wipe_code));
  REFUSED(fsm_msgLoadDevice(&load));
  REFUSED(fsm_msgResetDevice(&reset));
  REFUSED(fsm_msgApplySettings(&settings));
  REFUSED(fsm_msgApplyPolicies(&policies));
  REFUSED(fsm_msgRecoveryDevice(&recovery));
  EXPECT_EQ(2, kkconfirm_drain());
#undef REFUSED
  // Wipe still requires consent, including when firmware cannot read the
  // wallet.
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  WipeDevice wipe = {};
  fsm_test_clearLastFailure();
  fsm_msgWipeDevice(&wipe);
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(unchanged, flash);
  EXPECT_EQ(0, kkconfirm_drain());
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  fsm_test_clearLastFailure();
  fsm_msgWipeDevice(&wipe);
  EXPECT_EQ(0, fsm_test_lastFailureCode());
  EXPECT_FALSE(storage_isFirmwareTooOld());
  EXPECT_NE(unchanged, flash);
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST_F(ReviewHandlers, StorageReinitializationRecomputesFirmwareLock) {
  storage_commit();
  const auto normal_flash = flash;
  char record[STORAGE_SECTOR_LEN] = {};
  memcpy(record, "stor", 4);
  record[44] = STORAGE_VERSION + 1;
  std::fill(flash.begin(), flash.end(), 0xff);
  memcpy(flash.data() + 0x4000, record, sizeof(record));
  storage_init();
  ASSERT_TRUE(storage_isFirmwareTooOld());
  flash = normal_flash;
  storage_init();
  EXPECT_FALSE(storage_isFirmwareTooOld());
  EXPECT_FALSE(storage_isBitcoinOnlyLocked());
  LoadDevice load = {};
  load.has_mnemonic = true;
  strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);
  EXPECT_TRUE(storage_isInitialized());
}

static void expect_mnemonic_scratch_cleared() {
  for (char c : mnemonic_scratch_tokened) EXPECT_EQ(0, c);
  for (const auto& page : mnemonic_scratch_formatted)
    for (char c : page) EXPECT_EQ(0, c);
  for (char c : mnemonic_scratch_display) EXPECT_EQ(0, c);
  for (char c : mnemonic_scratch_word) EXPECT_EQ(0, c);
}

TEST_F(ReviewHandlers, ResetCancellationClearsScratchBeforeAndAfterFormatting) {
  const auto unchanged = flash;
  const uint8_t entropy[32] = {};
  for (int accepted : {0, 1}) {
    SCOPED_TRACE(accepted);
    reset_init(256, false, false, "english", "reset", false, 0, 0, false,
               false);
    ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
    // Exercise early cancellation with dirty shared scratch as well as the
    // cancellation reached after actual seed formatting.
    memset(mnemonic_scratch_formatted, 's', sizeof(mnemonic_scratch_formatted));
    memset(mnemonic_scratch_display, 's', sizeof(mnemonic_scratch_display));
    memset(mnemonic_scratch_word, 's', sizeof(mnemonic_scratch_word));
    ASSERT_TRUE(kkconfirm_preload(accepted, 1));
    reset_entropy(entropy, sizeof(entropy));
    EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
    EXPECT_FALSE(setup_isArmed());
    EXPECT_EQ(unchanged, flash);
    EXPECT_EQ(0, kkconfirm_drain());
    expect_mnemonic_scratch_cleared();
  }
}

TEST_F(ReviewHandlers, ResetWithoutBackupCommitsAndClearsScratch) {
  const uint8_t entropy[32] = {};
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  reset_init(128, false, false, "english", "reset", true, 0, 0, false, false);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  reset_entropy(entropy, sizeof(entropy));
  EXPECT_FALSE(setup_isArmed());
  EXPECT_EQ(0, fsm_test_lastFailureCode());
  EXPECT_EQ(0, kkconfirm_drain());
  EXPECT_TRUE(storage_isInitialized());
  EXPECT_STREQ("reset", storage_getLabel());
  expect_mnemonic_scratch_cleared();
}

TEST_F(ReviewHandlers, ResetBackupCommitsAllStrengthsAndClearsScratch) {
  const uint8_t entropy[32] = {};
  for (uint32_t strength : {128u, 192u, 256u}) {
    SCOPED_TRACE(strength);
    fsm_test_clearLastFailure();
    reset_init(strength, false, false, "english", "backed up", false, 0, 0,
               false, false);
    ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
    ASSERT_TRUE(kkconfirm_preload(20, 0));
    reset_entropy(entropy, sizeof(entropy));
    EXPECT_FALSE(setup_isArmed());
    EXPECT_EQ(0, fsm_test_lastFailureCode());
    EXPECT_GE(kkconfirm_drain(), 0);
    EXPECT_STREQ("backed up", storage_getLabel());
    const char* words = storage_getMnemonic();
    ASSERT_NE(nullptr, words);
    EXPECT_EQ(strength * 3 / 32,
              1u + std::count(words, words + strlen(words), ' '));
    expect_mnemonic_scratch_cleared();
  }
}

#if !BITCOIN_ONLY
static const uint8_t review_pubkey[33] = {
    0x02, 0xe3, 0xb3, 0x01, 0x5c, 0x47, 0xdd, 0xca, 0xab, 0xe4, 0xf8,
    0xe8, 0x72, 0xf1, 0xed, 0x8f, 0x09, 0xca, 0x14, 0x5a, 0x8d, 0x81,
    0x77, 0x0d, 0x92, 0x21, 0x3d, 0x56, 0xda, 0x31, 0xab, 0x51, 0x07};

TEST_F(ReviewHandlers, SessionEndClearsRuntimeSignerAndAlias) {
  ASSERT_TRUE(signed_metadata_store_signer(3, review_pubkey, "Session signer",
                                           nullptr, 0, 0, 0, false));
  ASSERT_TRUE(signed_metadata_signer_is_runtime(3));
  ASSERT_NE(nullptr, signed_metadata_signer_alias(3));
  ClearSession clear = {};
  fsm_msgClearSession(&clear);
  EXPECT_FALSE(signed_metadata_signer_is_runtime(3));
  EXPECT_EQ(nullptr, signed_metadata_signer_alias(3));

  ASSERT_TRUE(signed_metadata_store_signer(3, review_pubkey, "Next session",
                                           nullptr, 0, 0, 0, false));
  Initialize initialize = {};
  fsm_msgInitialize(&initialize);
  EXPECT_FALSE(signed_metadata_signer_is_runtime(3));
  EXPECT_EQ(nullptr, signed_metadata_signer_alias(3));
}

TEST_F(ReviewHandlers, ReopeningFlashClearsRuntimeSigner) {
  ASSERT_TRUE(signed_metadata_store_signer(3, review_pubkey, "Old wallet",
                                           nullptr, 0, 0, 0, false));
  ASSERT_TRUE(signed_metadata_signer_is_runtime(3));
  storage_init();
  EXPECT_FALSE(signed_metadata_signer_is_runtime(3));
  EXPECT_EQ(nullptr, signed_metadata_signer_alias(3));
}

TEST_F(ReviewHandlers, MetadataKeyIdRefusesNarrowingBeforeAck) {
  // The handler's AdvancedMode gate (added after 00b's version of this test)
  // answers ActionCancelled first; enable it so the key_id check is reached.
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  for (uint32_t key_id :
       {static_cast<uint32_t>(METADATA_MAX_KEYS), 256u, 0xffffffffu}) {
    EthereumTxMetadata msg = {};
    msg.has_key_id = true;
    msg.key_id = key_id;
    fsm_test_clearLastFailure();
    fsm_msgEthereumTxMetadata(&msg);
    EXPECT_EQ(FailureType_Failure_Other, fsm_test_lastFailureCode());
  }
}

TEST_F(ReviewHandlers, Bip85DerivationMatchesIndependentBip32Oracle) {
  char child[241] = {};
  ASSERT_TRUE(bip85_derive_mnemonic(12, 0, child, sizeof(child)));
  EXPECT_STREQ(
      "eternal siege creek hand combine grass name balance identify "
      "rude ozone truly",
      child);
  EXPECT_FALSE(bip85_derive_mnemonic(15, 0, child, sizeof(child)));
  EXPECT_FALSE(bip85_derive_mnemonic(12, 0x80000000u, child, sizeof(child)));
  GetBip85Mnemonic request = {};
  request.word_count = 12;
  request.index = 0;
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  fsm_test_clearLastFailure();
  fsm_msgGetBip85Mnemonic(&request);
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(0, kkconfirm_drain());

  ASSERT_TRUE(kkconfirm_preload(20, 0));
  fsm_test_clearLastFailure();
  fsm_msgGetBip85Mnemonic(&request);
  EXPECT_EQ(0, fsm_test_lastFailureCode());
  EXPECT_EQ(32, kkconfirm_drain());  // 20 pairs queued, 4 screens approved
  for (char byte : mnemonic_scratch_tokened) EXPECT_EQ(0, byte);
  for (const auto& page : mnemonic_scratch_formatted)
    for (char byte : page) EXPECT_EQ(0, byte);
  for (char byte : mnemonic_scratch_display) EXPECT_EQ(0, byte);
  for (char byte : mnemonic_scratch_word) EXPECT_EQ(0, byte);
}

#endif
