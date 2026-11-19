#ifndef MONERO_PROBE_H
#define MONERO_PROBE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool monero_probe_decrypt(const uint8_t key[32], const uint8_t iv[12],
                          const uint8_t blob[112], uint8_t plain[96]);
bool monero_probe_verify_signature(const uint8_t plain[96],
                                   const uint8_t out_key[32]);
void monero_probe_keccak(const uint8_t* data, size_t size, uint8_t out[32]);
void monero_probe_transcript_item(const uint8_t out_key[32],
                                  const uint8_t tx_pub[32], uint64_t index,
                                  uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif
