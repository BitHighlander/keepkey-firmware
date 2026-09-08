extern "C" {
#include "keepkey/board/usb.h"
#include "keepkey/firmware/ctap2.h"
#include "keepkey/firmware/u2f.h"
#include "trezor/crypto/hmac.h"
#include "u2f.h"
#include "u2f_knownapps.h"
}

#include "gtest/gtest.h"

#include <string>
#include <vector>

TEST(U2F, WordsFromData) {
  const uint8_t buff1[32] = "123456789012345678901";
  ASSERT_EQ(std::string(words_from_data(buff1, 6)),
            "couple muscle snack heavy");

  const uint8_t buff2[32] = "keepkeykeepkeykeepkey";
  ASSERT_EQ(std::string(words_from_data(buff2, 6)),
            "hidden clinic foster strategy");

  ASSERT_EQ(std::string(u2f_well_known[6].appname), "Bitbucket");
  ASSERT_EQ(std::string(words_from_data(u2f_well_known[6].appid, 6)),
            "bar peace tonight cement");
}

TEST(U2F, ShapeShift) {
  ASSERT_EQ(U2F_SHAPESHIFT_COM->appname, std::string("ShapeShift"));
  ASSERT_EQ(U2F_SHAPESHIFT_IO->appname, std::string("ShapeShift"));
  ASSERT_EQ(U2F_SHAPESHIFT_COM_STG->appname,
            std::string("ShapeShift (staging)"));
  ASSERT_EQ(U2F_SHAPESHIFT_IO_STG->appname,
            std::string("ShapeShift (staging)"));
  ASSERT_EQ(U2F_SHAPESHIFT_COM_DEV->appname, std::string("ShapeShift (dev)"));
  ASSERT_EQ(U2F_SHAPESHIFT_IO_DEV->appname, std::string("ShapeShift (dev)"));
}

TEST(U2F, AuthenticatorResetGenerationInvalidatesNewAndLegacyHandles) {
  uint8_t private_key[32], app_id[32], handle[64];
  uint8_t generation_before[PASSKEY_CREDENTIAL_GENERATION_SIZE];
  uint8_t generation_after[PASSKEY_CREDENTIAL_GENERATION_SIZE];
  memset(private_key, 0x11, sizeof(private_key));
  memset(app_id, 0x22, sizeof(app_id));
  memset(handle, 0x80, 32);  // public hardened derivation path
  memset(generation_before, 0x33, sizeof(generation_before));
  memset(generation_after, 0x44, sizeof(generation_after));

  uint8_t generation_keybase[32 + 32 + PASSKEY_CREDENTIAL_GENERATION_SIZE];
  memcpy(generation_keybase, app_id, 32);
  memcpy(generation_keybase + 32, handle, 32);
  memcpy(generation_keybase + 64, generation_before, sizeof(generation_before));
  hmac_sha256(private_key, sizeof(private_key), generation_keybase,
              sizeof(generation_keybase), handle + 32);
  EXPECT_TRUE(u2f_key_handle_authenticator_is_valid(private_key, app_id, handle,
                                                    generation_before, false));
  EXPECT_FALSE(u2f_key_handle_authenticator_is_valid(
      private_key, app_id, handle, generation_after, false));

  uint8_t legacy_keybase[64];
  memcpy(legacy_keybase, app_id, 32);
  memcpy(legacy_keybase + 32, handle, 32);
  hmac_sha256(private_key, sizeof(private_key), legacy_keybase,
              sizeof(legacy_keybase), handle + 32);
  EXPECT_TRUE(u2f_key_handle_authenticator_is_valid(private_key, app_id, handle,
                                                    generation_before, true));
  EXPECT_FALSE(u2f_key_handle_authenticator_is_valid(
      private_key, app_id, handle, generation_after, false));
}

namespace {

constexpr uint32_t kActiveCid = 0x11223344;
std::vector<U2FHID_FRAME> u2f_frames;

void capture_u2f_frame(const U2FHID_FRAME* frame) {
  u2f_frames.push_back(*frame);
}

void inject_competing_frames_during_user_presence(void) {
  U2FHID_FRAME init{};
  init.cid = CID_BROADCAST;
  init.init.cmd = U2FHID_INIT;
  init.init.bcntl = INIT_NONCE_SIZE;
  u2fhid_read(1, &init);

  U2FHID_FRAME foreign{};
  foreign.cid = kActiveCid;
  foreign.init.cmd = U2FHID_PING;
  u2fhid_read(1, &foreign);
}

bool saw_u2f_error(uint32_t cid, uint8_t error) {
  for (const U2FHID_FRAME& frame : u2f_frames) {
    if (frame.cid == cid && frame.init.cmd == U2FHID_ERROR &&
        frame.init.bcntl == 1 && frame.init.data[0] == error)
      return true;
  }
  return false;
}

}  // namespace

TEST(U2F, UserPresenceRejectsInitAndForeignCommandsWithoutChangingChannel) {
  ctap2_init();
  u2f_frames.clear();
  usb_set_u2f_tx_callback(capture_u2f_frame);
  u2f_set_user_presence_hook(inject_competing_frames_during_user_presence);

  U2FHID_FRAME request{};
  request.cid = kActiveCid;
  request.init.cmd = U2FHID_CBOR;
  request.init.bcntl = 1;
  request.init.data[0] = CTAP2_CMD_RESET;
  u2fhid_read(0, &request);

  u2f_set_user_presence_hook(nullptr);
  usb_set_u2f_tx_callback(nullptr);
  usbTiny(0);

  EXPECT_TRUE(saw_u2f_error(CID_BROADCAST, ERR_CHANNEL_BUSY));
  EXPECT_TRUE(saw_u2f_error(kActiveCid, ERR_CHANNEL_BUSY));

  bool sent_response_on_active_channel = false;
  for (const U2FHID_FRAME& frame : u2f_frames) {
    sent_response_on_active_channel =
        sent_response_on_active_channel ||
        (frame.cid == kActiveCid && frame.init.cmd == U2FHID_CBOR);
  }
  EXPECT_TRUE(sent_response_on_active_channel);
}
