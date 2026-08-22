extern "C" {
#include "keepkey/firmware/ctap2.h"
#include "keepkey/firmware/ctap2/cbor.h"
}

#include "gtest/gtest.h"

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
