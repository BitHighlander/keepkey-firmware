/* C-side helpers for monero.cpp: verifies what the device returns using the
 * trezor-crypto Monero primitives (built with USE_MONERO=1). */
#include "monero_probe.h"

#include <string.h>

#include "chacha20poly1305/rfc7539.h"
#include "memzero.h"
#include "monero/monero.h"

bool monero_probe_decrypt(const uint8_t key[32], const uint8_t iv[12],
                          const uint8_t blob[112], uint8_t plain[96]) {
  chacha20poly1305_ctx ctx;
  uint8_t tag[16];
  rfc7539_init(&ctx, key, iv);
  chacha20poly1305_decrypt(&ctx, blob, plain, 96);
  rfc7539_finish(&ctx, 0, 96, tag);
  memzero(&ctx, sizeof(ctx));
  return memcmp(tag, blob + 96, 16) == 0;
}

/* Core's one-member ring signature over the key image I = plain[0..32):
 * c == Hs(I || rG + cP || r*Hp(P) + cI). */
bool monero_probe_verify_signature(const uint8_t plain[96],
                                   const uint8_t out_key[32]) {
  ge25519 P, I, hp, L, R, t;
  bignum256modm c, r, check;
  uint8_t transcript[96], c_bytes[32];
  if (!ge25519_unpack_vartime(&P, out_key) || !ge25519_unpack_vartime(&I, plain))
    return false;
  expand_raw256_modm(c, plain + 32);
  expand_raw256_modm(r, plain + 64);
  ge25519_double_scalarmult_vartime(&L, &P, c, r);
  xmr_hash_to_ec(&hp, out_key, 32);
  ge25519_scalarmult(&R, &hp, r);
  ge25519_scalarmult(&t, &I, c);
  ge25519_add(&R, &R, &t, 0);
  memcpy(transcript, plain, 32);
  ge25519_pack(transcript + 32, &L);
  ge25519_pack(transcript + 64, &R);
  xmr_hash_to_scalar(check, transcript, sizeof(transcript));
  contract256_modm(c_bytes, check);
  return memcmp(c_bytes, plain + 32, 32) == 0;
}

void monero_probe_keccak(const uint8_t* data, size_t size, uint8_t out[32]) {
  xmr_fast_hash(out, data, size);
}

void monero_probe_transcript_item(const uint8_t out_key[32],
                                  const uint8_t tx_pub[32], uint64_t index,
                                  uint8_t out[32]) {
  uint8_t data[64 + 10];
  memcpy(data, out_key, 32);
  memcpy(data + 32, tx_pub, 32);
  const int n = xmr_write_varint(data + 64, 10, index);
  xmr_fast_hash(out, data, 64 + (size_t)n);
}
