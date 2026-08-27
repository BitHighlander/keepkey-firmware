extern "C" {
#include "keepkey/firmware/ctap2.h"
#include "keepkey/firmware/ctap2/cbor.h"
#include "keepkey/rand/rng_health.h"
}

#include "gtest/gtest.h"

#include <cstring>
#include <vector>

TEST(CTAP2, GetInfoAdvertisesSafeInitialCapabilities) {
  const uint8_t request[] = {CTAP2_CMD_GET_INFO};
  uint8_t response[256];
  size_t response_length = 0;
  ctap2_handle(request, sizeof(request), response, sizeof(response),
               &response_length);
  ASSERT_GT(response_length, 1u);
  ASSERT_EQ(response[0], CTAP2_OK);

  CborValue value;
  ASSERT_TRUE(cbor_map_find_int(response + 1, response_length - 1, 3, &value));
  ASSERT_EQ(value.type, CBOR_TYPE_BYTES);
  ASSERT_EQ(value.length, 16u);
  ASSERT_TRUE(cbor_map_find_int(response + 1, response_length - 1, 5, &value));
  ASSERT_EQ(value.type, CBOR_TYPE_UINT);
  ASSERT_EQ(value.value, 7609u);
}

TEST(CTAP2, RejectsUnknownAndMalformedCommands) {
  uint8_t response[8];
  size_t response_length = 0;
  ctap2_handle(nullptr, 0, response, sizeof(response), &response_length);
  ASSERT_EQ(response[0], CTAP2_ERR_INVALID_LENGTH);
  const uint8_t unknown[] = {0x7f};
  ctap2_handle(unknown, sizeof(unknown), response, sizeof(response),
               &response_length);
  ASSERT_EQ(response[0], CTAP2_ERR_INVALID_COMMAND);

  const uint8_t trailing_cbor[] = {CTAP2_CMD_CLIENT_PIN, 0xa0, 0x00};
  ctap2_handle(trailing_cbor, sizeof(trailing_cbor), response, sizeof(response),
               &response_length);
  ASSERT_EQ(response[0], CTAP2_ERR_INVALID_CBOR);
}

TEST(CTAP2, ClientPinReturnsP256KeyAgreement) {
  const uint8_t request[] = {
      CTAP2_CMD_CLIENT_PIN, 0xa2, 0x01, 0x01, 0x02, 0x02};
  uint8_t response[256];
  size_t response_length = 0;
  ctap2_handle(request, sizeof(request), response, sizeof(response),
               &response_length);
  ASSERT_GT(response_length, 1u);
  ASSERT_EQ(response[0], CTAP2_OK);
  const uint8_t* key;
  size_t key_length;
  ASSERT_TRUE(cbor_map_find_int_slice(response + 1, response_length - 1, 1,
                                      &key, &key_length));
  CborDecoder decoder;
  CborValue value;
  cbor_decoder_init(&decoder, key, key_length);
  ASSERT_TRUE(cbor_decode_value(&decoder, &value));
  ASSERT_EQ(value.type, CBOR_TYPE_MAP);
  ASSERT_EQ(value.value, 5u);
}

TEST(CTAP2, ClientPinKeyAgreementFailsClosedWithoutCheckedEntropy) {
  rng_health_force_verdict(false);
  ctap2_init();
  const uint8_t request[] = {
      CTAP2_CMD_CLIENT_PIN, 0xa2, 0x01, 0x01, 0x02, 0x02};
  uint8_t response[256] = {0};
  size_t response_length = 0;
  ctap2_handle(request, sizeof(request), response, sizeof(response),
               &response_length);
  ASSERT_EQ(response_length, 1u);
  EXPECT_EQ(response[0], CTAP2_ERR_OTHER);
  EXPECT_TRUE(ctap2_key_agreement_is_clear());
  rng_health_force_verdict(true);
}

TEST(CTAP2, ClientPinRejectsOutOfRangeP256PrivateKeys) {
  uint8_t private_key[32] = {0};
  EXPECT_FALSE(ctap2_key_agreement_private_is_valid(private_key));
  std::memset(private_key, 0xff, sizeof(private_key));
  EXPECT_FALSE(ctap2_key_agreement_private_is_valid(private_key));
  std::memset(private_key, 0, sizeof(private_key));
  private_key[31] = 1;
  EXPECT_TRUE(ctap2_key_agreement_private_is_valid(private_key));
}

TEST(CTAP2, ClientPinConsumesAndWipesKeyAgreementOnFirstUse) {
  rng_health_force_verdict(true);
  ctap2_init();
  const uint8_t get_key[] = {
      CTAP2_CMD_CLIENT_PIN, 0xa2, 0x01, 0x01, 0x02, 0x02};
  uint8_t response[256] = {0};
  size_t response_length = 0;
  ctap2_handle(get_key, sizeof(get_key), response, sizeof(response),
               &response_length);
  ASSERT_EQ(response[0], CTAP2_OK);
  ASSERT_FALSE(ctap2_key_agreement_is_clear());

  /* A structurally valid setPIN request that omits keyAgreement reaches the
   * one-shot ECDH consumer and must erase the pending private key on failure.
   */
  std::vector<uint8_t> consume = {
      CTAP2_CMD_CLIENT_PIN, 0xa4, 0x01, 0x01, 0x02, 0x03, 0x04, 0x50};
  consume.insert(consume.end(), 16, 0);
  consume.insert(consume.end(), {0x05, 0x58, 0x40});
  consume.insert(consume.end(), 64, 0);
  ctap2_handle(consume.data(), consume.size(), response, sizeof(response),
               &response_length);
  EXPECT_EQ(response[0], CTAP2_ERR_PIN_AUTH_INVALID);
  EXPECT_TRUE(ctap2_key_agreement_is_clear());
}
