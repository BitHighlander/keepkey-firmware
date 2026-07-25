/**
 * Copyright (c) 2026 KeepKey
 *
 * ZIP-316 helpers for Zcash unified address encoding.
 */

#ifndef __ZCASH_ZIP316_H__
#define __ZCASH_ZIP316_H__

#include <stddef.h>
#include <stdint.h>

#define ZCASH_ZIP316_F4JUMBLE_MIN_LEN 48
#define ZCASH_ZIP316_F4JUMBLE_MAX_LEN 4194368

#define ZCASH_ZIP316_ORCHARD_RAW_RECEIVER_LEN 43
#define ZCASH_ZIP316_PADDING_LEN 16
#define ZCASH_ZIP316_ORCHARD_ONLY_PAYLOAD_LEN \
  (2 + ZCASH_ZIP316_ORCHARD_RAW_RECEIVER_LEN + ZCASH_ZIP316_PADDING_LEN)
#define ZCASH_ZIP316_ORCHARD_ONLY_DATA5_LEN \
  ((ZCASH_ZIP316_ORCHARD_ONLY_PAYLOAD_LEN * 8 + 4) / 5)
#define ZCASH_ZIP316_ORCHARD_ONLY_MAX_HRP_LEN ZCASH_ZIP316_PADDING_LEN
#define ZCASH_ZIP316_ORCHARD_ONLY_MAX_ADDRESS_LEN \
  (ZCASH_ZIP316_ORCHARD_ONLY_MAX_HRP_LEN + 1 + \
   ZCASH_ZIP316_ORCHARD_ONLY_DATA5_LEN + 6)
#define ZCASH_ZIP316_ORCHARD_ONLY_MAX_ADDRESS_SIZE \
  (ZCASH_ZIP316_ORCHARD_ONLY_MAX_ADDRESS_LEN + 1)

int zcash_zip316_f4jumble(uint8_t *message, size_t message_len);
int zcash_zip316_f4jumble_inv(uint8_t *message, size_t message_len);

int zcash_zip316_encode_orchard_unified_address(
    const char *hrp,
    const uint8_t receiver[ZCASH_ZIP316_ORCHARD_RAW_RECEIVER_LEN],
    char *output, size_t output_len);

#endif
