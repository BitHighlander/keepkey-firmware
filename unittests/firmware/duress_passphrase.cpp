#include "gtest/gtest.h"
#include "test_board.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

extern "C" {
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/memory.h"
#include "keepkey/emulator/setup.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/passphrase_sm.h"
#include "keepkey/firmware/pin_sm.h"
#include "keepkey/firmware/signing.h"
#include "keepkey/firmware/storage.h"
#include "storage.h"
}

bool kkconfirm_preload_no_sentinel(int, int);
bool kkconfirm_sendTiny(uint16_t, const uint8_t*, uint8_t);
std::vector<uint16_t> kkconfirm_readResponseIds();
void kk_test_set_message_hook(std::function<void(MessageType, const void*)>);
void kkconfirm_capture_start();
std::vector<std::string> kkconfirm_capture_finish();

namespace {
const char kMnemonic[] = "all all all all all all all all all all all all";
const char kDuress[] = "erase the device under duress";

class DuressPassphrase : public ::testing::Test {
 protected:
  void SetUp() override {
    static bool initialized = false;
    if (!initialized) {
      setup();
      kk_test_board_init();
      storage_init();
      initialized = true;
    }
    storage_wipe();
    storage_reset();
    LoadDevice load = {};
    load.has_mnemonic = true;
    std::strcpy(load.mnemonic, kMnemonic);
    load.has_pin = true;
    std::strcpy(load.pin, "1234");
    load.has_passphrase_protection = load.passphrase_protection = true;
    storage_loadDevice(&load);
    storage_setLabel("duress-test");
    storage_commit();
    ASSERT_TRUE(kkconfirm_preload_no_sentinel(0, 0));
    fsm_test_clearLastFailure();
  }

  void TearDown() override {
    kk_test_set_message_hook({});
    kkconfirm_capture_finish();
    session_clear(true);
    storage_wipe();
    storage_reset();
    storage_commit();
  }

  // Exercise the real USB passphrase and PIN state machines, including the
  // randomized matrix. Respond only to requests actually emitted by firmware.
  void Respond(std::vector<std::string> phrases, int cancel_at = -1,
               bool cancel_pin = false) {
    kk_test_set_message_hook([phrases, cancel_at, cancel_pin,
                              index = size_t{0}](MessageType id,
                                                 const void*) mutable {
      if (id == MessageType_MessageType_ButtonRequest) {
        const uint8_t yes[] = {0x08, 0x01};
        EXPECT_TRUE(
            kkconfirm_sendTiny(MessageType_MessageType_ButtonAck, nullptr, 0));
        EXPECT_TRUE(kkconfirm_sendTiny(
            MessageType_MessageType_DebugLinkDecision, yes, sizeof(yes)));
      } else if (id == MessageType_MessageType_PinMatrixRequest) {
        if (cancel_pin) {
          EXPECT_TRUE(
              kkconfirm_sendTiny(MessageType_MessageType_Cancel, nullptr, 0));
        } else {
          uint8_t ack[] = {0x0a, 4, 0, 0, 0, 0};
          for (size_t i = 0; i < 4; ++i)
            ack[i + 2] = '1' + (std::strchr(get_pin_matrix(), "1234"[i]) -
                                get_pin_matrix());
          EXPECT_TRUE(kkconfirm_sendTiny(MessageType_MessageType_PinMatrixAck,
                                         ack, sizeof(ack)));
        }
      } else if (id == MessageType_MessageType_PassphraseRequest) {
        if (static_cast<int>(index) == cancel_at || index >= phrases.size()) {
          EXPECT_TRUE(
              kkconfirm_sendTiny(MessageType_MessageType_Cancel, nullptr, 0));
        } else {
          const auto& phrase = phrases[index];
          std::vector<uint8_t> ack = {0x0a,
                                      static_cast<uint8_t>(phrase.size())};
          ack.insert(ack.end(), phrase.begin(), phrase.end());
          EXPECT_TRUE(kkconfirm_sendTiny(MessageType_MessageType_PassphraseAck,
                                         ack.data(), ack.size()));
        }
        ++index;
      }
    });
  }

  void Configure(const std::vector<std::string>& phrases) {
    Respond(phrases);
    ChangeDuressPassphrase request = {};
    fsm_msgChangeDuressPassphrase(&request);
    kk_test_set_message_hook({});
  }

  void ExpectSingleTerminal(bool success) {
    const auto ids = kkconfirm_readResponseIds();
    EXPECT_EQ(success ? 1 : 0, std::count(ids.begin(), ids.end(),
                                          MessageType_MessageType_Success));
    EXPECT_EQ(success ? 0 : 1, std::count(ids.begin(), ids.end(),
                                          MessageType_MessageType_Failure));
  }
};

TEST_F(DuressPassphrase, SetupRequiresFreshPinAndTwoMatchingEntries) {
  ASSERT_TRUE(session_isPinCached());
  Configure({kDuress, kDuress});
  ASSERT_TRUE(storage_hasDuressPassphrase());
  ExpectSingleTerminal(true);
  storage_init();
  EXPECT_TRUE(storage_hasDuressPassphrase());
  EXPECT_TRUE(storage_hasPin());
  EXPECT_TRUE(storage_getPassphraseProtected());
}

TEST_F(DuressPassphrase, CancelledPinDoesNotReuseCachedAuthorization) {
  ASSERT_TRUE(session_isPinCached());
  Respond({}, -1, true);
  ChangeDuressPassphrase request = {};
  fsm_msgChangeDuressPassphrase(&request);
  EXPECT_FALSE(storage_hasDuressPassphrase());
  ExpectSingleTerminal(false);
}

TEST_F(DuressPassphrase,
       MismatchAndEmptyAndCancelledEntryPreserveExistingValue) {
  ASSERT_TRUE(storage_setDuressPassphrase(kDuress));
  storage_commit();
  Configure({"different", "mismatch"});
  EXPECT_TRUE(storage_hasDuressPassphrase());
  ExpectSingleTerminal(false);
  ASSERT_TRUE(kkconfirm_preload_no_sentinel(0, 0));
  Configure({""});
  EXPECT_TRUE(storage_hasDuressPassphrase());
  ExpectSingleTerminal(false);
  ASSERT_TRUE(kkconfirm_preload_no_sentinel(0, 0));
  Respond({"different"}, 1);
  ChangeDuressPassphrase request = {};
  fsm_msgChangeDuressPassphrase(&request);
  EXPECT_TRUE(storage_hasDuressPassphrase());
  ExpectSingleTerminal(false);
  EXPECT_TRUE(storage_wipeIfDuressPassphrase(kDuress));
}

TEST_F(DuressPassphrase, OrdinaryAndEmptyPassphrasesStillOpenWallets) {
  ASSERT_TRUE(storage_setDuressPassphrase(kDuress));
  storage_commit();
  for (const auto& phrase : {std::string("normal wallet"), std::string("")}) {
    Respond({phrase});
    EXPECT_TRUE(passphrase_protect());
    EXPECT_TRUE(session_isPassphraseCached());
    EXPECT_TRUE(storage_isInitialized());
    session_clear(false);
  }
}

TEST_F(DuressPassphrase,
       MatchAbortsOperationWithoutDisplayingOrConfirmingSecret) {
  ASSERT_TRUE(storage_setDuressPassphrase(kDuress));
  storage_commit();
  // Fill more than one rotated storage sector with a wallet record.
  storage_commit();
  storage_commit();
  const std::string uuid = storage_getUuidStr();
  std::array<uint8_t, 64> old_ciphertext;
  std::memcpy(old_ciphertext.data(),
              reinterpret_cast<const uint8_t*>(
                  flash_write_helper(storage_getLocation())) +
                  44 + 1501,
              old_ciphertext.size());
  SignTx start = {};
  start.inputs_count = start.outputs_count = 1;
  HDNode root = {};
  signing_init(&start, coinByName("Bitcoin"), &root);
  ASSERT_TRUE(signing_is_active());
  Respond({kDuress});
  kkconfirm_capture_start();
  GetPublicKey request = {};
  fsm_msgGetPublicKey(&request);
  ExpectSingleTerminal(false);
  const auto screens = kkconfirm_capture_finish();
  EXPECT_TRUE(screens.empty());
  EXPECT_FALSE(session_isPinCached());
  EXPECT_FALSE(session_isPassphraseCached());
  EXPECT_FALSE(storage_isInitialized());
  EXPECT_FALSE(storage_hasDuressPassphrase());
  EXPECT_FALSE(storage_hasPin());
  EXPECT_FALSE(storage_getPassphraseProtected());
  EXPECT_STRNE(uuid.c_str(), storage_getUuidStr());
  EXPECT_FALSE(signing_is_active());
  for (int sector = FLASH_STORAGE1; sector <= FLASH_STORAGE3; ++sector) {
    const auto* data = reinterpret_cast<const uint8_t*>(
        flash_write_helper(static_cast<Allocation>(sector)));
    EXPECT_EQ(data + STORAGE_SECTOR_LEN,
              std::search(data, data + STORAGE_SECTOR_LEN,
                          old_ciphertext.begin(), old_ciphertext.end()));
    // Old encrypted wallet payloads must be gone from every sector; the new
    // empty record and its marker may occupy only their bounded prefix.
    EXPECT_TRUE(std::all_of(data + 2580, data + STORAGE_SECTOR_LEN,
                            [](uint8_t b) { return b == 0xff; }));
  }
  storage_init();
  EXPECT_FALSE(storage_isInitialized());
  EXPECT_FALSE(storage_hasDuressPassphrase());
}

TEST_F(DuressPassphrase, ExactBytesAndMaximumLength) {
  const std::string phrase(50, 'x');
  ASSERT_TRUE(storage_setDuressPassphrase(phrase.c_str()));
  EXPECT_FALSE(storage_setDuressPassphrase(std::string(51, 'x').c_str()));
  EXPECT_FALSE(storage_wipeIfDuressPassphrase(std::string(49, 'x').c_str()));
  EXPECT_FALSE(storage_wipeIfDuressPassphrase((phrase + "x").c_str()));
  EXPECT_TRUE(storage_wipeIfDuressPassphrase(phrase.c_str()));
}

TEST_F(DuressPassphrase, EmbeddedNulCannotTruncateToTheTrigger) {
  ASSERT_TRUE(storage_setDuressPassphrase(kDuress));
  storage_commit();
  Respond({std::string(kDuress) + '\0' + "suffix"});
  EXPECT_FALSE(passphrase_protect());
  EXPECT_TRUE(storage_isInitialized());
  EXPECT_TRUE(storage_hasDuressPassphrase());
  ExpectSingleTerminal(false);
}

TEST_F(DuressPassphrase,
       DisablingPassphrasesOrRemovingPinRequiresDuressRemoval) {
  ASSERT_TRUE(storage_setDuressPassphrase(kDuress));
  ApplySettings settings = {};
  settings.has_use_passphrase = true;
  settings.use_passphrase = false;
  fsm_msgApplySettings(&settings);
  EXPECT_TRUE(storage_getPassphraseProtected());
  ExpectSingleTerminal(false);
  ASSERT_TRUE(kkconfirm_preload_no_sentinel(0, 0));
  ChangePin pin = {};
  pin.has_remove = pin.remove = true;
  fsm_msgChangePin(&pin);
  EXPECT_TRUE(storage_hasPin());
  ExpectSingleTerminal(false);
  ASSERT_TRUE(kkconfirm_preload_no_sentinel(0, 0));
  Respond({});
  ChangeDuressPassphrase remove = {};
  remove.has_remove = remove.remove = true;
  fsm_msgChangeDuressPassphrase(&remove);
  ExpectSingleTerminal(true);
  storage_init();
  EXPECT_FALSE(storage_hasDuressPassphrase());
  EXPECT_FALSE(storage_wipeIfDuressPassphrase(kDuress));
}

TEST_F(DuressPassphrase, V20RandomReservedBytesCannotArmDuressOnUpgrade) {
  ConfigFlash loaded = {};
  SessionState session = {};
  char flash[STORAGE_SECTOR_LEN] = {};
  std::memcpy(
      flash,
      reinterpret_cast<const void*>(flash_write_helper(storage_getLocation())),
      sizeof(flash));
  std::memset(flash + 44 + 1440, 1, 49);
#if BITCOIN_ONLY
  const uint32_t version = STORAGE_VERSION_BTC_ONLY_BASE + 20;
#else
  const uint32_t version = 20;
#endif
  std::memcpy(flash + 44, &version, sizeof(version));
  EXPECT_EQ(SUS_Updated, storage_fromFlash(&session, &loaded, flash));
  EXPECT_EQ(0, loaded.storage.pub.duress.enabled);
  EXPECT_TRUE(loaded.storage.pub.has_mnemonic);
  EXPECT_TRUE(loaded.storage.pub.has_pin);
  EXPECT_TRUE(loaded.storage.pub.passphrase_protection);
  EXPECT_STREQ("duress-test", loaded.storage.pub.label);
  EXPECT_EQ(0, std::memcmp(flash + 44 + 1501, loaded.storage.encrypted_sec,
                           sizeof(loaded.storage.encrypted_sec)));
}

}  // namespace
