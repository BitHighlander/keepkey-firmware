extern "C" {
#include "keepkey/firmware/ctap2/cbor.h"
}

#include "gtest/gtest.h"

#include <cstring>

TEST(CTAP2CBOR, CanonicalRoundTrip) {
  uint8_t buffer[64];
  CborEncoder encoder;
  cbor_encoder_init(&encoder, buffer, sizeof(buffer));
  ASSERT_TRUE(cbor_encode_map(&encoder, 2));
  ASSERT_TRUE(cbor_encode_uint(&encoder, 1));
  ASSERT_TRUE(cbor_encode_text(&encoder, "ok", 2));
  ASSERT_TRUE(cbor_encode_uint(&encoder, 2));
  ASSERT_TRUE(
      cbor_encode_bytes(&encoder, reinterpret_cast<const uint8_t*>("abc"), 3));

  CborValue value;
  ASSERT_TRUE(
      cbor_map_find_int(buffer, cbor_encoder_size(&encoder), 1, &value));
  ASSERT_EQ(value.type, CBOR_TYPE_TEXT);
  ASSERT_EQ(value.length, 2u);
  ASSERT_EQ(0, memcmp(value.data, "ok", 2));
  ASSERT_TRUE(
      cbor_map_find_int(buffer, cbor_encoder_size(&encoder), 2, &value));
  ASSERT_EQ(value.type, CBOR_TYPE_BYTES);
  ASSERT_EQ(value.length, 3u);
}

TEST(CTAP2CBOR, RejectsIndefiniteAndNonCanonicalValues) {
  const uint8_t indefinite[] = {0x9f, 0xff};
  const uint8_t noncanonical[] = {0x18, 0x17};
  CborDecoder decoder;
  CborValue value;
  cbor_decoder_init(&decoder, indefinite, sizeof(indefinite));
  ASSERT_FALSE(cbor_decode_value(&decoder, &value));
  cbor_decoder_init(&decoder, noncanonical, sizeof(noncanonical));
  ASSERT_FALSE(cbor_decode_value(&decoder, &value));
}

TEST(CTAP2CBOR, RejectsTrailingInvalidUtf8AndExcessiveNesting) {
  const uint8_t trailing[] = {0xa0, 0x00};
  const uint8_t invalid_utf8[] = {0x62, 0xc0, 0x80};
  uint8_t nested[18];
  memset(nested, 0x81, sizeof(nested));
  nested[sizeof(nested) - 1] = 0x00;
  ASSERT_FALSE(cbor_validate(trailing, sizeof(trailing)));
  ASSERT_FALSE(cbor_validate(invalid_utf8, sizeof(invalid_utf8)));
  ASSERT_FALSE(cbor_validate(nested, sizeof(nested)));
}

TEST(CTAP2CBOR, EncoderReportsOverflow) {
  uint8_t buffer[2];
  CborEncoder encoder;
  cbor_encoder_init(&encoder, buffer, sizeof(buffer));
  ASSERT_FALSE(cbor_encode_text(&encoder, "passkey", 7));
  ASSERT_EQ(cbor_encoder_size(&encoder), 0u);
}
