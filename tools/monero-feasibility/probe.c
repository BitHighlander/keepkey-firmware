/* Link-only Cortex-M3 reachability probe. No startup code or USB handlers. */
#include <stdint.h>
#include <stddef.h>
#include "ed25519-donna/ed25519.h"
#include "hasher.h"
#if USE_MONERO
#include "monero/monero.h"
#endif

/* Public synthetic inputs and an observable sink prevent dead-code removal. */
volatile uint8_t monero_probe_input[32] = {1, 2, 3};
volatile uint8_t monero_probe_sink;

void monero_probe(void) {
  uint8_t seed[32], pub[32], digest[32];
  for (unsigned i = 0; i < 32; ++i) seed[i] = monero_probe_input[i];
  /* Existing firmware primitives retained identically in both links. */
  ed25519_publickey(seed, pub);
  hasher_Raw(HASHER_SHA3K, pub, sizeof(pub), digest);
#if USE_MONERO
  bignum256modm spend, view, sub, derived;
  ge25519 spend_pub, view_pub, derivation, output, image, commitment;
  uint8_t payload[64];
  char address[100];
  xmr_hash_to_scalar(spend, seed, sizeof(seed));
  contract256_modm(digest, spend);
  xmr_hash_to_scalar(view, digest, sizeof(digest));
  ge25519_scalarmult_base_wrapper(&spend_pub, spend);
  ge25519_scalarmult_base_wrapper(&view_pub, view);
  ge25519_pack(payload, &spend_pub);
  ge25519_pack(payload + 32, &view_pub);
  int len = xmr_base58_addr_encode_check(18, payload, sizeof(payload), address, sizeof(address));
  xmr_get_subaddress_secret_key(sub, 0, 1, view);
  xmr_generate_key_derivation(&derivation, &view_pub, spend);
  xmr_derive_private_key(derived, &derivation, 0, spend);
  xmr_derive_public_key(&output, &derivation, 0, &spend_pub);
  ge25519_pack(digest, &output);
  xmr_hash_to_ec(&image, digest, sizeof(digest));
  ge25519_scalarmult(&image, &image, derived);
  ge25519_pack(digest, &image);
  xmr_gen_c(&commitment, sub, 1000000000000ULL);
  ge25519_pack(pub, &commitment);
  monero_probe_sink = (uint8_t)len ^ (uint8_t)address[0] ^ pub[0];
#endif
  monero_probe_sink ^= digest[0];
}
