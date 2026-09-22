#include <stddef.h>
#include <stdint.h>

#include "trezor/crypto/sha2.h"

/* Standalone crypto tests do not link the emulator process/flash setup. Keep
 * their RNG dependency local and deterministic; production and the full
 * emulator continue to use lib/emulator/setup.c. */
void emulatorRandom(void* buffer, size_t size) {
  static uint64_t counter = 1;
  uint8_t* out = (uint8_t*)buffer;
  while (size != 0) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    sha256_Raw((const uint8_t*)&counter, sizeof(counter), digest);
    counter++;
    const size_t take = size < sizeof(digest) ? size : sizeof(digest);
    for (size_t i = 0; i < take; i++) out[i] = digest[i];
    out += take;
    size -= take;
  }
}
