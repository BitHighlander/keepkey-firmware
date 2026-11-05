#ifndef KEEPKEY_FIRMWARE_SAFE_BATCH_H
#define KEEPKEY_FIRMWARE_SAFE_BATCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bounded locator for one CALL in canonical MultiSend(bytes). The entire
 * batch is validated on each pass; no delegatecall or unreviewed tail can
 * hide after the selected call. Offsets include the multiSend selector. */
#define SAFE_BATCH_MAX_CALLS 64u
#define SAFE_BATCH_PREFIX 68u
typedef struct {
  uint32_t total, received, packed_end, next, payload_end;
  uint32_t offset, length;
  uint16_t wanted, count;
  uint8_t to[20], value[32], prefix[SAFE_BATCH_PREFIX];
  uint8_t prefix_length;
  bool selected, failed;
} SafeBatch;

bool safe_batch_begin(SafeBatch* batch, uint32_t total, uint16_t wanted);
bool safe_batch_feed(SafeBatch* b, const uint8_t* bytes, size_t length);
bool safe_batch_finish(const SafeBatch* b);

#endif
