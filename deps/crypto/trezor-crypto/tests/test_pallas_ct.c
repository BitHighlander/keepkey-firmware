/*
 * Secret-flow regression harness for Pallas scalar multiplication.
 *
 * With VALGRIND=1, scalar bytes are marked undefined before multiplication.
 * Memcheck then reports any conditional branch or memory address derived from
 * the scalar (the standard ctgrind technique already used by test_check.c).
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if VALGRIND
#include <valgrind/memcheck.h>
#include <valgrind/valgrind.h>
#endif

#include "pallas_ct.h"

static const curve_point PALLAS_GENERATOR = {
    {/* x = p - 1 */ {0x00000000, 0x09698768, 0x133e46e6, 0x0d31f812,
                      0x00000224, 0x00000000, 0x00000000, 0x00000000,
                      0x00400000}},
    {/* y = 2 */ {0x00000002, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                  0x00000000, 0x00000000, 0x00000000, 0x00000000}},
};

static bignum256 scalar_with_bit(unsigned bit) {
  bignum256 scalar = {{0}};
  scalar.val[bit / BN_BITS_PER_LIMB] = UINT32_C(1) << (bit % BN_BITS_PER_LIMB);
  return scalar;
}

static bignum256 dense_scalar(void) {
  bignum256 scalar;
  size_t i;
  for (i = 0; i < BN_LIMBS - 1; ++i) {
    scalar.val[i] = BN_LIMB_MASK;
  }
  scalar.val[BN_LIMBS - 1] = (UINT32_C(1) << 22) - 1;
  return scalar;
}

static bignum256 max_256(void) {
  bignum256 value;
  size_t i;
  for (i = 0; i < BN_LIMBS - 1; ++i) {
    value.val[i] = BN_LIMB_MASK;
  }
  value.val[BN_LIMBS - 1] = UINT32_C(0x00ffffff);
  return value;
}

static void multiply_secret(const bignum256* input, curve_point* result) {
  bignum256 scalar = *input;
#if VALGRIND
  VALGRIND_MAKE_MEM_UNDEFINED(&scalar, sizeof(scalar));
#endif
  pallas_ct_point_mult(&scalar, &PALLAS_GENERATOR, result);
#if VALGRIND
  VALGRIND_MAKE_MEM_DEFINED(&scalar, sizeof(scalar));
  VALGRIND_MAKE_MEM_DEFINED(result, sizeof(*result));
#endif
  memset(&scalar, 0, sizeof(scalar));
}

static void normalize_secret(const bignum256* input) {
  bignum256 scalar = *input;
#if VALGRIND
  VALGRIND_MAKE_MEM_UNDEFINED(&scalar, sizeof(scalar));
#endif
  pallas_ct_scalar_replace_zero_with_one(&scalar);
#if VALGRIND
  VALGRIND_MAKE_MEM_DEFINED(&scalar, sizeof(scalar));
#endif
  memset(&scalar, 0, sizeof(scalar));
}

int main(void) {
  const bignum256 scalars[] = {
      {{0}},
      scalar_with_bit(0),
      scalar_with_bit(17),
      scalar_with_bit(254),
      dense_scalar(),
      max_256(),
  };
  const curve_point identity = {{{0}}, {{0}}};
  curve_point result;
  size_t i;

#if VALGRIND
  if (!RUNNING_ON_VALGRIND) {
    fprintf(stderr, "VALGRIND=1 harness must run under Valgrind\n");
    return 2;
  }
#endif

  for (i = 0; i < sizeof(scalars) / sizeof(scalars[0]); ++i) {
    normalize_secret(&scalars[i]);
    multiply_secret(&scalars[i], &result);
  }

  multiply_secret(&scalars[0], &result);
  if (memcmp(&result, &identity, sizeof(result)) != 0) {
    fprintf(stderr, "zero scalar did not produce the identity\n");
    return 1;
  }

  multiply_secret(&scalars[1], &result);
  if (memcmp(&result, &PALLAS_GENERATOR, sizeof(result)) != 0) {
    fprintf(stderr, "one scalar did not reproduce the generator\n");
    return 1;
  }

  memset(&result, 0, sizeof(result));
  puts("Pallas constant-time secret-flow harness: PASS");
  return 0;
}
