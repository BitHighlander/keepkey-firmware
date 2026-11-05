/* Public fixtures only. The same test body executes on host and ARM.
 * This is an experiment, not a wallet API or firmware command handler. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "monero/monero.h"
#include "memzero.h"
#include "interop_vectors.h"

volatile uint32_t monero_checks;
volatile uint32_t monero_fail_line;
volatile uint32_t monero_phase;
volatile uint32_t monero_boundary_index;
volatile uint32_t monero_boundary_need;
volatile int32_t monero_boundary_written;

#define VERIFY(x) do { ++monero_checks; if (!(x)) { \
  monero_fail_line = __LINE__; return 1; } } while (0)

/* Avoid the raw writer's positive return on a truncated encoding. */
static int bounded_varint(uint8_t *out, size_t capacity, uint64_t value) {
  if ((size_t)xmr_size_varint(value) > capacity) return -1;
  return xmr_write_varint(out, capacity, value);
}

static const uint8_t scalar_order[32] = {
  0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,
  0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10
};

/* Decode canonically and require a nonidentity point in the prime subgroup.
 * Validation is on public inputs. No secret-dependent variable-time multiply. */
static int public_point(ge25519 *out, const uint8_t encoded[32]) {
  uint8_t canonical[32], product[32], identity[32] = {1};
  bignum256modm order;
  ge25519 check;
  /* The upstream positive-unpack wrapper negates coordinates even on error. */
  ge25519_set_neutral(out);
  if (!ge25519_unpack_vartime(out, encoded)) return 0;
  ge25519_pack(canonical, out);
  if (memcmp(canonical, encoded, 32) || !memcmp(canonical, identity, 32)) return 0;
  expand_raw256_modm(order, scalar_order);
  ge25519_scalarmult(&check, out, order);
  ge25519_pack(product, &check);
  return memcmp(product, identity, 32) == 0;
}

/* Research boundary: check the scalar and the key pair before creating an
 * image. A future firmware handler must derive its own output secret. */
static int checked_key_image(uint8_t out[32], const uint8_t pub[32],
                             const uint8_t secret[32]) {
  bignum256modm scalar;
  ge25519 point, computed, image;
  uint8_t calculated[32];
  int ok = 0;
  expand_raw256_modm(scalar, secret);
  if (iszero256_modm(scalar) || !is_reduced256_modm(scalar)) goto done;
  if (!public_point(&point, pub)) goto done;
  ge25519_scalarmult_base_wrapper(&computed, scalar);
  ge25519_pack(calculated, &computed);
  if (memcmp(calculated, pub, 32)) goto done;
  xmr_hash_to_ec(&image, pub, 32);
  ge25519_scalarmult(&image, &image, scalar);
  ge25519_pack(out, &image);
  ok = 1;
done:
  memzero(scalar, sizeof(scalar));
  memzero(&point, sizeof(point));
  memzero(&computed, sizeof(computed));
  memzero(&image, sizeof(image));
  memzero(calculated, sizeof(calculated));
  return ok;
}

int monero_interop_run(void) {
  monero_checks = 0;
  monero_fail_line = 0;
  for (size_t i = 0; i < MONERO_REFERENCE_CASE_COUNT; ++i) {
    monero_phase = (uint32_t)i + 1;
    const monero_reference_case *v = &monero_reference_cases[i];
    bignum256modm spend, view, sub, tx, derived;
    ge25519 B, A, D, C, R, recv_derivation, send_derivation, output, image;
    uint8_t bytes[64], expected[32], secret[32];
    char address[96];
    int is_main = v->major == 0 && v->minor == 0;

    /* Trezor-compatible SLIP-0010 key seed: reduce directly, do not hash. */
    expand256_modm(spend, v->key_seed, 32);
    contract256_modm(bytes, spend);
    VERIFY(!memcmp(bytes, v->spend_secret, 32));
    xmr_hash_to_scalar(view, bytes, 32);
    contract256_modm(bytes, view);
    VERIFY(!memcmp(bytes, v->view_secret, 32));
    ge25519_scalarmult_base_wrapper(&B, spend);
    ge25519_scalarmult_base_wrapper(&A, view);
    ge25519_pack(bytes, &B);
    VERIFY(!memcmp(bytes, v->spend_public, 32));
    ge25519_pack(bytes, &A);
    VERIFY(!memcmp(bytes, v->view_public, 32));
    if (is_main) {
      ge25519_copy(&D, &B);
      ge25519_copy(&C, &A);
      set256_modm(sub, 0);
    } else {
      xmr_get_subaddress_secret_key(sub, v->major, v->minor, view);
      ge25519_scalarmult_base_wrapper(&D, sub);
      ge25519_add(&D, &D, &B, 0);
      ge25519_scalarmult(&C, &D, view);
    }
    ge25519_pack(bytes, &D);
    ge25519_pack(bytes + 32, &C);
    VERIFY(!memcmp(bytes, v->sub_spend_public, 32));
    VERIFY(!memcmp(bytes + 32, v->sub_view_public, 32));
    int address_len = xmr_base58_addr_encode_check(is_main ? 18 : 42, bytes, 64,
                                                   address, sizeof(address));
    VERIFY(address_len == 95);
    VERIFY(!memcmp(address, v->address, 95));
    uint64_t tag = 0;
    VERIFY(xmr_base58_addr_decode_check(address, 95, &tag, bytes, 64) == 64);
    VERIFY(tag == (uint64_t)(is_main ? 18 : 42));
    VERIFY(!memcmp(bytes, v->sub_spend_public, 32));
    VERIFY(!memcmp(bytes + 32, v->sub_view_public, 32));
    address[94] = address[94] == '1' ? '2' : '1';
    VERIFY(xmr_base58_addr_decode_check(address, 95, &tag, bytes, 64) == 0);
    VERIFY(xmr_base58_addr_encode_check(is_main ? 18 : 42, bytes, 64, address, 1) == 0);

    /* Generate an incoming output with independent sender and recipient paths. */
    expand_raw256_modm(tx, v->tx_secret);
    VERIFY(is_reduced256_modm(tx) && !iszero256_modm(tx));
    if (is_main) ge25519_scalarmult_base_wrapper(&R, tx);
    else ge25519_scalarmult(&R, &D, tx);
    ge25519_pack(bytes, &R);
    VERIFY(!memcmp(bytes, v->tx_public, 32));
    xmr_generate_key_derivation(&recv_derivation, &R, view);
    xmr_generate_key_derivation(&send_derivation, &C, tx);
    ge25519_pack(bytes, &recv_derivation);
    ge25519_pack(expected, &send_derivation);
    VERIFY(!memcmp(bytes, v->derivation, 32));
    VERIFY(!memcmp(bytes, expected, 32));
    xmr_derive_private_key(derived, &recv_derivation, v->output_index, spend);
    if (!is_main) add256_modm(derived, derived, sub);
    contract256_modm(secret, derived);
    VERIFY(!memcmp(secret, v->output_secret, 32));
    xmr_derive_public_key(&output, &send_derivation, v->output_index, &D);
    ge25519_pack(bytes, &output);
    VERIFY(!memcmp(bytes, v->output_public, 32));
    ge25519_scalarmult_base_wrapper(&image, derived);
    ge25519_pack(expected, &image);
    VERIFY(!memcmp(bytes, expected, 32));
    VERIFY(checked_key_image(bytes, v->output_public, secret));
    VERIFY(!memcmp(bytes, v->key_image, 32));

    /* A valid point paired with the wrong secret must not yield an image. */
    memset(bytes, 0xa5, 32);
    memcpy(expected, bytes, 32);
    secret[0] ^= 1;
    VERIFY(!checked_key_image(bytes, v->output_public, secret));
    VERIFY(!memcmp(bytes, expected, 32));
    VERIFY(!checked_key_image(bytes, v->output_public, scalar_order));
    /* A lifted scalar has the SAME public key; only canonicality rejects it. */
    unsigned carry = 0;
    for (unsigned j = 0; j < 32; ++j) {
      unsigned sum = (unsigned)v->output_secret[j] + scalar_order[j] + carry;
      secret[j] = (uint8_t)sum;
      carry = sum >> 8;
    }
    VERIFY(!checked_key_image(bytes, v->output_public, secret));
    VERIFY(!memcmp(bytes, expected, 32));
    memset(secret, 0, 32);
    VERIFY(!checked_key_image(bytes, v->output_public, secret));
    memzero(spend, sizeof(spend)); memzero(view, sizeof(view));
    memzero(sub, sizeof(sub)); memzero(tx, sizeof(tx));
    memzero(derived, sizeof(derived)); memzero(secret, sizeof(secret));
  }
  monero_phase = 0xffffffff;
  {
    ge25519 point;
    uint8_t identity[32] = {1}, zero[32] = {0}, invalid[32];
    memset(invalid, 0xff, 32);
    VERIFY(!public_point(&point, identity));
    VERIFY(!public_point(&point, zero)); /* order-four point */
    VERIFY(!public_point(&point, invalid));
    VERIFY(public_point(&point, monero_reference_cases[0].spend_public));
    const uint64_t values[] = {0,127,128,16383,16384,UINT32_MAX,UINT64_MAX};
    for (size_t i = 0; i < sizeof(values)/sizeof(values[0]); ++i) {
      uint8_t buf[10], copy[10];
      memset(buf, 0xa5, sizeof(buf)); memcpy(copy, buf, sizeof(buf));
      int need = xmr_size_varint(values[i]);
      monero_boundary_index = (uint32_t)i;
      monero_boundary_need = (uint32_t)need;
      VERIFY(bounded_varint(buf, (size_t)need - 1, values[i]) == -1);
      VERIFY(!memcmp(buf, copy, sizeof(buf)));
      monero_boundary_written = bounded_varint(buf, sizeof(buf), values[i]);
      VERIFY(monero_boundary_written == need);
      uint64_t decoded = 0;
      VERIFY(xmr_read_varint(buf, (size_t)need, &decoded) == need);
      VERIFY(decoded == values[i]);
    }
  }
  monero_phase = 0;
  return 0;
}

#ifndef MONERO_ARM
#include <stdio.h>
#include <stdlib.h>
void random_buffer(uint8_t *out, size_t len) { (void)out; (void)len; abort(); }
int main(void) {
  int status = monero_interop_run();
  printf("{\"cases\":%u,\"checks\":%u,\"failed_line\":%u,\"status\":%d}\n",
    (unsigned)MONERO_REFERENCE_CASE_COUNT, (unsigned)monero_checks,
    (unsigned)monero_fail_line, status);
  return status;
}
#endif
