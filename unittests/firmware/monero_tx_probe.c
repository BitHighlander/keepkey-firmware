#include "monero_tx_probe.h"

#include <string.h>

#include "chacha20poly1305/rfc7539.h"
#include "memzero.h"
#include "monero/base58.h"
#include "monero/monero.h"
#include "monero_test_rng.h"

static const uint8_t PROBE_SEED[32] = "KeepKey 7.17 Monero tx vectors";

void monero_tx_probe_scalar(uint8_t out[32], const char* label, uint32_t ctr) {
  uint8_t h[32];
  bignum256modm s;
  xmr_test_stream(h, label, PROBE_SEED, ctr);
  expand256_modm(s, h, 32);
  contract256_modm(out, s);
}

void monero_tx_probe_point(uint8_t out[32], const char* label, uint32_t ctr) {
  uint8_t k[32];
  bignum256modm s;
  ge25519 P;
  monero_tx_probe_scalar(k, label, ctr);
  expand256_modm(s, k, 32);
  ge25519_scalarmult_base_wrapper(&P, s);
  ge25519_pack(out, &P);
}

static void subaddress_scalar(bignum256modm m, const bignum256modm view,
                              uint32_t major, uint32_t minor) {
  uint8_t data[48] = {'S', 'u', 'b', 'A', 'd', 'd', 'r', 0};
  contract256_modm(data + 8, view);
  memcpy(data + 40, &major, 4);
  memcpy(data + 44, &minor, 4);
  xmr_hash_to_scalar(m, data, sizeof(data));
}

void monero_tx_probe_address_keys(const uint8_t spend[32],
                                  const uint8_t view[32], uint32_t major,
                                  uint32_t minor, uint8_t keys[64]) {
  bignum256modm b, a, m;
  ge25519 D, C, M;
  expand256_modm(b, spend, 32);
  expand256_modm(a, view, 32);
  ge25519_scalarmult_base_wrapper(&D, b);
  if (major || minor) {
    subaddress_scalar(m, a, major, minor);
    ge25519_scalarmult_base_wrapper(&M, m);
    ge25519_add(&D, &D, &M, 0);
    ge25519_scalarmult(&C, &D, a);
  } else {
    ge25519_scalarmult_base_wrapper(&C, a);
  }
  ge25519_pack(keys, &D);
  ge25519_pack(keys + 32, &C);
}

void monero_tx_probe_subaddress_view_secret(const uint8_t spend[32],
                                            const uint8_t view[32],
                                            uint32_t major, uint32_t minor,
                                            uint8_t secret[32]) {
  bignum256modm b, a, m;
  expand256_modm(b, spend, 32);
  expand256_modm(a, view, 32);
  subaddress_scalar(m, a, major, minor);
  add256_modm(b, b, m);
  mul256_modm(a, a, b);
  contract256_modm(secret, a);
}

void monero_tx_probe_owned(const uint8_t spend[32], const uint8_t view[32],
                           uint32_t major, uint32_t minor, uint32_t index,
                           uint64_t amount, bool via_additional,
                           const char* label, uint32_t ctr,
                           MoneroTxProbeOwned* out) {
  bignum256modm b, a, m, r, hs, x, mask;
  ge25519 D, R, deriv, P, C;
  uint8_t keys[64], rb[32];
  memset(out, 0, sizeof(*out));
  expand256_modm(b, spend, 32);
  expand256_modm(a, view, 32);
  monero_tx_probe_address_keys(spend, view, major, minor, keys);
  ge25519_unpack_vartime(&D, keys);
  monero_tx_probe_scalar(rb, label, ctr * 4u);
  expand256_modm(r, rb, 32);
  if (major || minor)
    ge25519_scalarmult(&R, &D, r);
  else
    ge25519_scalarmult_base_wrapper(&R, r);
  /* The wallet's side of the derivation: 8*a*R. */
  xmr_generate_key_derivation(&deriv, &R, a);
  xmr_derivation_to_scalar(hs, &deriv, index);
  add256_modm(x, hs, b);
  if (major || minor) {
    subaddress_scalar(m, a, major, minor);
    add256_modm(x, x, m);
  }
  ge25519_scalarmult_base_wrapper(&P, x);
  ge25519_pack(out->out_key, &P);
  contract256_modm(out->secret, x);
  if (via_additional) {
    ge25519_pack(out->additional, &R);
    monero_tx_probe_point(out->tx_pub, label, ctr * 4u + 1u);
  } else {
    ge25519_pack(out->tx_pub, &R);
  }
  monero_tx_probe_scalar(out->mask, label, ctr * 4u + 2u);
  expand256_modm(mask, out->mask, 32);
  xmr_gen_c(&C, mask, amount);
  ge25519_pack(out->commitment, &C);
}

bool monero_tx_probe_open(const uint8_t key[32], uint32_t position,
                          const uint8_t* sealed, size_t size, uint8_t* plain) {
  chacha20poly1305_ctx ctx;
  uint8_t tag[16], nonce[12] = {0};
  if (size < 16) return false;
  memcpy(nonce, &position, 4);
  rfc7539_init(&ctx, key, nonce);
  chacha20poly1305_decrypt(&ctx, sealed, plain, size - 16);
  rfc7539_finish(&ctx, 0, (int64_t)(size - 16), tag);
  memzero(&ctx, sizeof(ctx));
  return memcmp(tag, sealed + size - 16, 16) == 0;
}

bool monero_tx_probe_decode_address(const char* address, uint64_t* tag,
                                    uint8_t* data, size_t* size) {
  /* prefix byte, 64 or 72 bytes, 4-byte Keccak checksum */
  uint8_t buf[1 + 72 + 4] = {0}, hash[32];
  const size_t length = strlen(address);
  /* xmr_base58_decode() does not report the decoded size. */
  size_t n = length == 95 ? 69u : length == 106 ? 77u : 0u, capacity = n;
  if (!n || n - 5 > *size ||
      !xmr_base58_decode(address, length, buf, &capacity))
    return false;
  xmr_fast_hash(hash, buf, n - 4);
  if (memcmp(hash, buf + n - 4, 4)) return false;
  *tag = buf[0];
  *size = n - 5;
  memcpy(data, buf + 1, *size);
  return true;
}

void monero_tx_probe_bad_points(uint8_t small_order[32], uint8_t torsioned[32],
                                uint8_t noncanonical[32]) {
  /* A point of order 8 (from the ed25519 small-order list). */
  static const uint8_t order8[32] = {
      0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4,
      0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6,
      0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05};
  ge25519 T, P;
  uint8_t base[32];
  memcpy(small_order, order8, 32);
  monero_tx_probe_point(base, "torsion", 0);
  ge25519_unpack_vartime(&T, order8);
  ge25519_unpack_vartime(&P, base);
  ge25519_add(&P, &P, &T, 0);
  ge25519_pack(torsioned, &P);
  /* y = p + 1: decodes like y = 1 where a decoder reduces, never canonical. */
  memset(noncanonical, 0xff, 32);
  noncanonical[0] = 0xee;
  noncanonical[31] = 0x7f;
}
