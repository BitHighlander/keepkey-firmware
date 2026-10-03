extern "C" {
#include "keepkey/firmware/u2f.h"
#include "trezor/crypto/hmac.h"
#include "u2f.h"
#include "u2f_knownapps.h"
}

#include "gtest/gtest.h"

#include <string>

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
