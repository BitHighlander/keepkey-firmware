/* Host-only adapter to the independently pinned Monero Core crypto sources.
 * Inputs are public disposable test fixtures. This file is not firmware code.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "crypto-ops.h"
#include "keccak.h"

void ref_reduce(uint8_t out[32], const uint8_t in[32]) {
  memcpy(out, in, 32);
  sc_reduce32(out);
}

void ref_hash(uint8_t out[32], const uint8_t *in, size_t len) {
  keccak(in, len, out, 32);
}

void ref_base(uint8_t out[32], const uint8_t scalar[32]) {
  ge_p3 p;
  ge_scalarmult_base(&p, scalar);
  ge_p3_tobytes(out, &p);
}

int ref_mul(uint8_t out[32], const uint8_t point[32], const uint8_t scalar[32]) {
  ge_p3 p;
  ge_p2 result;
  if (ge_frombytes_vartime(&p, point) != 0) return -1;
  ge_scalarmult(&result, scalar, &p);
  ge_tobytes(out, &result);
  return 0;
}

int ref_add(uint8_t out[32], const uint8_t left[32], const uint8_t right[32]) {
  ge_p3 a, b, result;
  ge_cached cached;
  ge_p1p1 sum;
  if (ge_frombytes_vartime(&a, left) != 0 ||
      ge_frombytes_vartime(&b, right) != 0) return -1;
  ge_p3_to_cached(&cached, &b);
  ge_add(&sum, &a, &cached);
  ge_p1p1_to_p3(&result, &sum);
  ge_p3_tobytes(out, &result);
  return 0;
}

void ref_hp(uint8_t out[32], const uint8_t *in, size_t len) {
  uint8_t hash[32];
  ge_p2 p, result;
  ge_p1p1 cleared;
  ref_hash(hash, in, len);
  ge_fromfe_frombytes_vartime(&p, hash);
  ge_mul8(&cleared, &p);
  ge_p1p1_to_p2(&result, &cleared);
  ge_tobytes(out, &result);
}
