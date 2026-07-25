/**
 * Copyright (c) 2026 KeepKey
 *
 * Minimal ZIP-316 helpers needed for Orchard-only unified addresses.
 */

#include "zcash_zip316.h"

#include <stdint.h>
#include <string.h>

#include "blake2b.h"
#include "memzero.h"

#define ZCASH_ZIP316_BLAKE2B_OUT_LEN 64

static const char BECH32_CHARSET[] =
    "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static size_t min_size(size_t a, size_t b) { return a < b ? a : b; }

static size_t ceil_div(size_t num, size_t den) {
  return (num + den - 1) / den;
}

static int valid_f4jumble_len(size_t len) {
  return len >= ZCASH_ZIP316_F4JUMBLE_MIN_LEN &&
         len <= ZCASH_ZIP316_F4JUMBLE_MAX_LEN;
}

static void xor_bytes(uint8_t *target, size_t target_len, const uint8_t *source,
                      size_t source_len) {
  size_t len = min_size(target_len, source_len);
  for (size_t i = 0; i < len; i++) {
    target[i] ^= source[i];
  }
}

static int h_round(uint8_t *left, size_t left_len, const uint8_t *right,
                   size_t right_len, uint8_t round) {
  uint8_t personal[BLAKE2B_PERSONALBYTES] = {
      'U', 'A', '_', 'F', '4', 'J', 'u', 'm',
      'b', 'l', 'e', '_', 'H', round, 0,   0,
  };
  uint8_t hash[ZCASH_ZIP316_BLAKE2B_OUT_LEN];
  BLAKE2B_CTX ctx;

  if (blake2b_InitPersonal(&ctx, left_len, personal, sizeof(personal)) != 0) {
    memzero(hash, sizeof(hash));
    memzero(&ctx, sizeof(ctx));
    return -1;
  }
  if (blake2b_Update(&ctx, right, right_len) != 0 ||
      blake2b_Final(&ctx, hash, left_len) != 0) {
    memzero(hash, sizeof(hash));
    memzero(&ctx, sizeof(ctx));
    return -1;
  }
  xor_bytes(left, left_len, hash, left_len);

  memzero(hash, sizeof(hash));
  memzero(&ctx, sizeof(ctx));
  return 0;
}

static int g_round(const uint8_t *left, size_t left_len, uint8_t *right,
                   size_t right_len, uint8_t round) {
  uint8_t hash[ZCASH_ZIP316_BLAKE2B_OUT_LEN];
  for (size_t j = 0; j < ceil_div(right_len, ZCASH_ZIP316_BLAKE2B_OUT_LEN);
       j++) {
    uint8_t personal[BLAKE2B_PERSONALBYTES] = {
        'U',
        'A',
        '_',
        'F',
        '4',
        'J',
        'u',
        'm',
        'b',
        'l',
        'e',
        '_',
        'G',
        round,
        (uint8_t)(j & 0xff),
        (uint8_t)(j >> 8),
    };
    BLAKE2B_CTX ctx;

    if (j > 0xffff) {
      memzero(hash, sizeof(hash));
      return -1;
    }
    if (blake2b_InitPersonal(&ctx, sizeof(hash), personal, sizeof(personal)) !=
        0) {
      memzero(hash, sizeof(hash));
      memzero(&ctx, sizeof(ctx));
      return -1;
    }
    if (blake2b_Update(&ctx, left, left_len) != 0 ||
        blake2b_Final(&ctx, hash, sizeof(hash)) != 0) {
      memzero(hash, sizeof(hash));
      memzero(&ctx, sizeof(ctx));
      return -1;
    }
    xor_bytes(right + j * ZCASH_ZIP316_BLAKE2B_OUT_LEN,
              right_len - j * ZCASH_ZIP316_BLAKE2B_OUT_LEN, hash,
              sizeof(hash));
    memzero(&ctx, sizeof(ctx));
  }

  memzero(hash, sizeof(hash));
  return 0;
}

static int f4jumble_apply(uint8_t *message, size_t message_len, int inverse) {
  if (!message || !valid_f4jumble_len(message_len)) return -1;

  size_t left_len = min_size(ZCASH_ZIP316_BLAKE2B_OUT_LEN, message_len / 2);
  uint8_t *left = message;
  uint8_t *right = message + left_len;
  size_t right_len = message_len - left_len;

  if (inverse) {
    return h_round(left, left_len, right, right_len, 1) == 0 &&
                   g_round(left, left_len, right, right_len, 1) == 0 &&
                   h_round(left, left_len, right, right_len, 0) == 0 &&
                   g_round(left, left_len, right, right_len, 0) == 0
               ? 0
               : -1;
  }

  return g_round(left, left_len, right, right_len, 0) == 0 &&
                 h_round(left, left_len, right, right_len, 0) == 0 &&
                 g_round(left, left_len, right, right_len, 1) == 0 &&
                 h_round(left, left_len, right, right_len, 1) == 0
             ? 0
             : -1;
}

int zcash_zip316_f4jumble(uint8_t *message, size_t message_len) {
  return f4jumble_apply(message, message_len, 0);
}

int zcash_zip316_f4jumble_inv(uint8_t *message, size_t message_len) {
  return f4jumble_apply(message, message_len, 1);
}

static uint32_t bech32_polymod_step(uint32_t pre) {
  uint8_t b = pre >> 25;
  return ((pre & 0x1FFFFFF) << 5) ^
         (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
         (-((b >> 1) & 1) & 0x26508e6dUL) ^
         (-((b >> 2) & 1) & 0x1ea119faUL) ^
         (-((b >> 3) & 1) & 0x3d4233ddUL) ^
         (-((b >> 4) & 1) & 0x2a1462b3UL);
}

static int convert_bits_8_to_5(uint8_t *out, size_t *out_len,
                               size_t out_capacity, const uint8_t *in,
                               size_t in_len) {
  uint32_t val = 0;
  int bits = 0;
  *out_len = 0;

  while (in_len--) {
    val = (val << 8) | *(in++);
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      if (*out_len >= out_capacity) return -1;
      out[(*out_len)++] = (val >> bits) & 0x1f;
    }
  }
  if (bits) {
    if (*out_len >= out_capacity) return -1;
    out[(*out_len)++] = (val << (5 - bits)) & 0x1f;
  }
  return 0;
}

static int bech32m_encode_5bit(char *output, size_t output_len,
                               const char *hrp, const uint8_t *data,
                               size_t data_len) {
  uint32_t chk = 1;
  size_t hrp_len = 0;
  while (hrp[hrp_len] != 0) {
    int ch = hrp[hrp_len];
    if (ch < 33 || ch > 126 || (ch >= 'A' && ch <= 'Z')) {
      return -1;
    }
    chk = bech32_polymod_step(chk) ^ (ch >> 5);
    hrp_len++;
  }

  if (hrp_len == 0 || output_len < hrp_len + 1 + data_len + 6 + 1) {
    return -1;
  }

  chk = bech32_polymod_step(chk);
  for (size_t i = 0; i < hrp_len; i++) {
    chk = bech32_polymod_step(chk) ^ (hrp[i] & 0x1f);
    output[i] = hrp[i];
  }
  output[hrp_len] = '1';

  for (size_t i = 0; i < data_len; i++) {
    if (data[i] >> 5) return -1;
    chk = bech32_polymod_step(chk) ^ data[i];
    output[hrp_len + 1 + i] = BECH32_CHARSET[data[i]];
  }

  for (size_t i = 0; i < 6; i++) {
    chk = bech32_polymod_step(chk);
  }
  chk ^= 0x2bc830a3UL;

  for (size_t i = 0; i < 6; i++) {
    output[hrp_len + 1 + data_len + i] =
        BECH32_CHARSET[(chk >> ((5 - i) * 5)) & 0x1f];
  }
  output[hrp_len + 1 + data_len + 6] = 0;
  return 0;
}

static int bech32m_encode_bytes(char *output, size_t output_len,
                                const char *hrp, const uint8_t *data,
                                size_t data_len) {
  if (!output || !hrp || (!data && data_len != 0)) return -1;

  size_t data5_capacity = (data_len * 8 + 4) / 5;
  uint8_t data5[ZCASH_ZIP316_ORCHARD_ONLY_DATA5_LEN];
  if (data5_capacity > sizeof(data5)) return -1;

  size_t data5_len = 0;
  if (convert_bits_8_to_5(data5, &data5_len, sizeof(data5), data, data_len) !=
      0) {
    memzero(data5, sizeof(data5));
    return -1;
  }

  int ret = bech32m_encode_5bit(output, output_len, hrp, data5, data5_len);
  memzero(data5, sizeof(data5));
  return ret;
}

int zcash_zip316_encode_orchard_unified_address(
    const char *hrp,
    const uint8_t receiver[ZCASH_ZIP316_ORCHARD_RAW_RECEIVER_LEN],
    char *output, size_t output_len) {
  if (!hrp || !receiver || !output) return -1;

  size_t hrp_len = strlen(hrp);
  if (hrp_len == 0 || hrp_len > ZCASH_ZIP316_PADDING_LEN) return -1;

  uint8_t payload[ZCASH_ZIP316_ORCHARD_ONLY_PAYLOAD_LEN] = {0};
  payload[0] = 0x03; /* Orchard receiver typecode. */
  payload[1] = ZCASH_ZIP316_ORCHARD_RAW_RECEIVER_LEN;
  memcpy(payload + 2, receiver, ZCASH_ZIP316_ORCHARD_RAW_RECEIVER_LEN);
  memcpy(payload + 2 + ZCASH_ZIP316_ORCHARD_RAW_RECEIVER_LEN, hrp, hrp_len);

  int ret = zcash_zip316_f4jumble(payload, sizeof(payload));
  if (ret == 0) {
    ret = bech32m_encode_bytes(output, output_len, hrp, payload,
                               sizeof(payload));
  }

  memzero(payload, sizeof(payload));
  return ret;
}
