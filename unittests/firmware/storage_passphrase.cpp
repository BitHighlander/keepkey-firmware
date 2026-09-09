#include "gtest/gtest.h"

#include <cstring>
#include <vector>

extern "C" {
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/timer.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/transport/interface.h"
#include "keepkey/emulator/setup.h"
#include "trezor/crypto/bip39.h"
#include "trezor/crypto/curves.h"
#include "trezor/crypto/memzero.h"
}

namespace {
bool capture_flash_operations = false;
std::vector<std::vector<uint8_t>> commit_snapshots;
}

extern "C" void emulator_flash_operation_completed(void) {
  if (capture_flash_operations) {
    commit_snapshots.emplace_back(emulator_flash_base,
                                  emulator_flash_base + FLASH_TOTAL_SIZE);
  }
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
      if (layout_get_canvas() == nullptr) {
        timer_init();
        layout_init(display_canvas_init());
      }
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

TEST_F(PassphraseTransition, WalletSurvivesEveryCompletedCommitOperation) {
  storage_setLabel("before");
  storage_commit();
  commit_snapshots.clear();
  capture_flash_operations = true;
  storage_setLabel("after");
  storage_commit();
  capture_flash_operations = false;
  ASSERT_EQ(commit_snapshots.size(), 7u);
  // Snapshot 4 has the replacement marker; snapshot 5 publishes its magic.
  // Replay each partial byte prefix of that final four-byte programming step.
  const auto before_magic = commit_snapshots[4];
  const auto after_magic = commit_snapshots[5];
  size_t magic_offset = 0;
  for (Allocation a : {FLASH_STORAGE1, FLASH_STORAGE2, FLASH_STORAGE3}) {
    const size_t offset = static_cast<size_t>(flash_write_helper(a) -
                           reinterpret_cast<intptr_t>(emulator_flash_base));
    if (std::memcmp(before_magic.data() + offset, STORAGE_MAGIC_STR, 4) != 0 &&
        std::memcmp(after_magic.data() + offset, STORAGE_MAGIC_STR, 4) == 0) {
      magic_offset = offset;
    }
  }
  ASSERT_NE(magic_offset, 0u);
  for (size_t bytes = 1; bytes < STORAGE_MAGIC_LEN; ++bytes) {
    auto torn = before_magic;
    std::memcpy(torn.data() + magic_offset, after_magic.data() + magic_offset, bytes);
    commit_snapshots.push_back(std::move(torn));
  }
  const size_t first_partial_payload = commit_snapshots.size();
  // The spare was erased in snapshot 0; snapshot 1 contains the full payload.
  // Stop in the header, ciphertext and trailer, including one byte short.
  for (size_t bytes : {size_t{1}, size_t{4}, size_t{512}, size_t{1500},
                       size_t{2568}, STORAGE_RECORD_LEN - STORAGE_MAGIC_LEN - 1}) {
    auto torn = commit_snapshots[0];
    std::memcpy(torn.data() + magic_offset + STORAGE_MAGIC_LEN,
                commit_snapshots[1].data() + magic_offset + STORAGE_MAGIC_LEN,
                bytes);
    commit_snapshots.push_back(std::move(torn));
  }
  // A legacy record has no CRC: a torn erase can leave its magic intact
  // while damaging a field. The complete pending replacement must win.
  auto legacy_torn_erase = commit_snapshots[1];
  for (Allocation a : {FLASH_STORAGE1, FLASH_STORAGE2, FLASH_STORAGE3}) {
    const size_t offset = static_cast<size_t>(flash_write_helper(a) -
                           reinterpret_cast<intptr_t>(emulator_flash_base));
    if (std::memcmp(legacy_torn_erase.data() + offset, STORAGE_MAGIC_STR, 4) == 0) {
      std::memset(legacy_torn_erase.data() + offset + STORAGE_RECORD_DATA_LEN,
                  0xff, 8);
      legacy_torn_erase[offset + 44 + 32] |= 0x80;
    }
  }
  const size_t legacy_torn_index = commit_snapshots.size();
  commit_snapshots.push_back(std::move(legacy_torn_erase));
  for (size_t i = 0; i < commit_snapshots.size(); ++i) {
    SCOPED_TRACE(i);
    std::memcpy(emulator_flash_base, commit_snapshots[i].data(), FLASH_TOTAL_SIZE);
    storage_init();
    ASSERT_TRUE(storage_isInitialized());
    const char* label = storage_getLabel();
    if (i >= first_partial_payload && i < legacy_torn_index)
      EXPECT_STREQ("before", label);
    if (i == legacy_torn_index) EXPECT_STREQ("after", label);
    ASSERT_TRUE(std::strcmp(label, "before") == 0 ||
                std::strcmp(label, "after") == 0);
    HDNode node = {};
    ASSERT_TRUE(storage_getRootNode(SECP256K1_NAME, false, &node));
    ExpectWallet("", node);
    memzero(&node, sizeof(node));
  }
  commit_snapshots.clear();
}
