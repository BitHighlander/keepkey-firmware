#include "keepkey/firmware/safe_batch.h"

#include <string.h>

bool safe_batch_begin(SafeBatch* batch, uint32_t total, uint16_t wanted) {
  if (!batch) return false;
  memset(batch, 0, sizeof(*batch));
  batch->total = total;
  batch->wanted = wanted;
  batch->next = 68;
  batch->failed = total < 68 || wanted >= SAFE_BATCH_MAX_CALLS;
  return !batch->failed;
}

bool safe_batch_feed(SafeBatch* b, const uint8_t* bytes, size_t length) {
  static const uint8_t selector[4] = {0x8d, 0x80, 0xff, 0x0a};
  if (!b || !bytes || b->failed || b->received > b->total ||
      length > b->total - b->received)
    return false;
  for (size_t i = 0; i < length; i++) {
    const uint32_t at = b->received++;
    const uint8_t v = bytes[i];
    if (at < 4) {
      if (v != selector[at]) goto invalid;
    } else if (at < 36) {
      if (v != (at == 35 ? 32 : 0)) goto invalid;
    } else if (at < 68) {
      if (at < 64 && v != 0) goto invalid;
      b->packed_end = (b->packed_end << 8) | v;
      if (at == 67) {
        const uint32_t size = b->packed_end;
        if (!size || size > b->total - 68 ||
            (uint64_t)((size + 31ull) / 32ull) * 32ull != b->total - 68)
          goto invalid;
        b->packed_end += 68;
      }
    } else if (at >= b->packed_end) {
      if (v != 0 || b->next != b->packed_end) goto invalid;
    } else if (at - b->next < 85u) {
      const uint32_t h = at - b->next;
      if (h == 0) {
        if (v != 0 || b->count >= SAFE_BATCH_MAX_CALLS ||
            b->packed_end - b->next < 85)
          goto invalid;
        b->payload_end = 0;
      } else if (h <= 20 && b->count == b->wanted) {
        b->to[h - 1] = v;
      } else if (h <= 52 && b->count == b->wanted) {
        b->value[h - 21] = v;
      } else if (h >= 53) {
        if (h < 81 && v != 0) goto invalid;
        b->payload_end = (b->payload_end << 8) | v;
      }
      if (h == 84) {
        const uint32_t size = b->payload_end;
        if (size > b->packed_end - b->next - 85u) goto invalid;
        b->payload_end = b->next + 85u + size;
        if (b->count == b->wanted) {
          b->offset = b->next + 85u;
          b->length = size;
          b->selected = true;
        }
      }
    } else if (b->count == b->wanted && b->prefix_length < sizeof(b->prefix)) {
      b->prefix[b->prefix_length++] = v;
    }
    if (at >= 68 && at < b->packed_end && at + 1u == b->payload_end) {
      b->next = b->payload_end;
      b->count++;
    }
  }
  return true;
invalid:
  b->failed = true;
  return false;
}

bool safe_batch_finish(const SafeBatch* b) {
  return b && !b->failed && b->received == b->total &&
         b->next == b->packed_end && b->selected && b->count > b->wanted;
}
