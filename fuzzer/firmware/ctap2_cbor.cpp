extern "C" {
#include "keepkey/firmware/ctap2/cbor.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  (void)cbor_validate(data, size);
  CborDecoder decoder;
  cbor_decoder_init(&decoder, data, size);
  (void)cbor_skip_value(&decoder);

  CborValue value;
  for (uint64_t key = 1; key <= 9; ++key)
    (void)cbor_map_find_int(data, size, key, &value);
  return 0;
}
