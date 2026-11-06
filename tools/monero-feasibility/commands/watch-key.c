/* Authorized watch-only credential export for the emulator experiment. */
#include "watch-key.h"

#if !USE_MONERO
#error "Monero watch-key research requires Monero primitives"
#endif

#include <string.h>
#include "memzero.h"
#include "monero/monero.h"

bool monero_research_get_watch_key(
    const uint8_t node_key[32], uint32_t network, uint8_t watch_key[32],
    char address[MONERO_RESEARCH_ADDRESS_CAPACITY]) {
  struct {
    bignum256modm spend, view;
    uint8_t spend_bytes[32], hash[32];
    Hasher hasher;
  } scratch = {0};
  bool ok = false;
  if (watch_key) memzero(watch_key, 32);
  if (address) memzero(address, MONERO_RESEARCH_ADDRESS_CAPACITY);
  if (!node_key || !watch_key || !address || network >= 3) goto cleanup;
  if (!monero_research_get_address(node_key, network, 0, 0, address)) goto cleanup;
  expand256_modm(scratch.spend, node_key, 32);
  if (iszero256_modm(scratch.spend)) goto cleanup;
  contract256_modm(scratch.spend_bytes, scratch.spend);
  hasher_Init(&scratch.hasher, HASHER_SHA3K);
  hasher_Update(&scratch.hasher, scratch.spend_bytes, sizeof(scratch.spend_bytes));
  hasher_Final(&scratch.hasher, scratch.hash);
  expand256_modm(scratch.view, scratch.hash, sizeof(scratch.hash));
  if (iszero256_modm(scratch.view)) goto cleanup;
  contract256_modm(watch_key, scratch.view);
  ok = true;
cleanup:
  memzero(&scratch, sizeof(scratch));
  if (!ok) {
    if (watch_key) memzero(watch_key, 32);
    if (address) memzero(address, MONERO_RESEARCH_ADDRESS_CAPACITY);
  }
  return ok;
}
