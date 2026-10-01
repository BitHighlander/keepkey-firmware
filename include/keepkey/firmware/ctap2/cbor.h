/*
 * Minimal, allocation-free CBOR support for CTAP2.
 *
 * Only definite-length values used by CTAP are accepted. Keeping the parser
 * deliberately small also makes it practical to fuzz and audit on the STM32.
 */
#ifndef KEEPKEY_FIRMWARE_CTAP2_CBOR_H
#define KEEPKEY_FIRMWARE_CTAP2_CBOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
  CBOR_TYPE_UINT = 0,
  CBOR_TYPE_NEGINT = 1,
  CBOR_TYPE_BYTES = 2,
  CBOR_TYPE_TEXT = 3,
  CBOR_TYPE_ARRAY = 4,
  CBOR_TYPE_MAP = 5,
  CBOR_TYPE_TAG = 6,
  CBOR_TYPE_SIMPLE = 7,
} CborType;

typedef struct {
  uint8_t* buffer;
  size_t capacity;
  size_t offset;
  bool failed;
} CborEncoder;

typedef struct {
  const uint8_t* buffer;
  size_t length;
  size_t offset;
} CborDecoder;

typedef struct {
  CborType type;
  uint64_t value;
  const uint8_t* data;
  size_t length;
} CborValue;

void cbor_encoder_init(CborEncoder* encoder, uint8_t* buffer, size_t capacity);
bool cbor_encode_uint(CborEncoder* encoder, uint64_t value);
bool cbor_encode_int(CborEncoder* encoder, int64_t value);
bool cbor_encode_bytes(CborEncoder* encoder, const uint8_t* value,
                       size_t length);
bool cbor_encode_text(CborEncoder* encoder, const char* value, size_t length);
bool cbor_encode_bool(CborEncoder* encoder, bool value);
bool cbor_encode_array(CborEncoder* encoder, size_t count);
bool cbor_encode_map(CborEncoder* encoder, size_t pairs);
size_t cbor_encoder_size(const CborEncoder* encoder);

void cbor_decoder_init(CborDecoder* decoder, const uint8_t* buffer,
                       size_t length);
bool cbor_decode_value(CborDecoder* decoder, CborValue* value);
bool cbor_skip_value(CborDecoder* decoder);
bool cbor_validate(const uint8_t* buffer, size_t length);
bool cbor_map_find_int(const uint8_t* buffer, size_t length, uint64_t key,
                       CborValue* value);
bool cbor_map_find_int_slice(const uint8_t* buffer, size_t length, uint64_t key,
                             const uint8_t** value, size_t* value_length);

#endif
