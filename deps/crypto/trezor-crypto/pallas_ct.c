/**
 * Constant-time Pallas arithmetic for Zcash Orchard secret scalars.
 *
 * The field representation and Montgomery constants are derived from
 * zcash/pasta_curves 0.5.1.  Point formulas follow its Jacobian formulas, but
 * exceptional cases are computed and selected with masks rather than secret-
 * dependent branches.  Scalar multiplication always executes 255 rounds and
 * computes both the double and add result in every round.
 *
 * Constant-time here means control flow and memory access do not depend on
 * secret scalar or field values.  Physical leakage resistance still requires
 * inspection of the compiled target and measurement on the device.
 * The radix-2^16 multiplier deliberately avoids the Cortex-M3's
 * operand-dependent UMULL/UMLAL instructions.
 */

#include "pallas_ct.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "memzero.h"

enum { CT_LIMBS = 8 };

typedef struct {
  uint32_t v[CT_LIMBS];
} ct_fe;

typedef struct {
  ct_fe x;
  ct_fe y;
  ct_fe z;
} ct_point;

typedef struct {
  ct_fe modulus;
  ct_fe r2;
  ct_fe one;
} ct_modulus;

static const ct_modulus CT_P = {
    /* p */ {{0x00000001, 0x992d30ed, 0x094cf91b, 0x224698fc, 0x00000000,
              0x00000000, 0x00000000, 0x40000000}},
    /* R^2 mod p */
    {{0x0000000f, 0x8c78ecb3, 0x8b0de0e7, 0xd7d30dbd, 0xc3c95d18, 0x7797a99b,
      0x7b9cb714, 0x096d41af}},
    /* R mod p */
    {{0xfffffffd, 0x34786d38, 0xe41914ad, 0x992c350b, 0xffffffff, 0xffffffff,
      0xffffffff, 0x3fffffff}},
};

static const ct_modulus CT_Q = {
    /* q */ {{0x00000001, 0x8c46eb21, 0x0994a8dd, 0x224698fc, 0x00000000,
              0x00000000, 0x00000000, 0x40000000}},
    /* R^2 mod q */
    {{0x0000000f, 0xfc9678ff, 0x891a16e3, 0x67bb433d, 0x04ccf590, 0x7fae2310,
      0x7ccfdaa9, 0x096d41af}},
    /* R mod q */
    {{0xfffffffd, 0x5b2b3e9c, 0xe3420567, 0x992c350b, 0xffffffff, 0xffffffff,
      0xffffffff, 0x3fffffff}},
};

/* p - 2, in normal little-endian 32-bit limbs. */
static const uint32_t CT_P_MINUS_2[CT_LIMBS] = {
    0xffffffff, 0x992d30ec, 0x094cf91b, 0x224698fc,
    0x00000000, 0x00000000, 0x00000000, 0x40000000,
};

#ifdef PALLAS_CT_TESTING
static pallas_ct_counts ct_counts;
#define CT_COUNT(member) (ct_counts.member++)

void pallas_ct_test_reset_counts(void) {
  memset(&ct_counts, 0, sizeof(ct_counts));
}

void pallas_ct_test_get_counts(pallas_ct_counts* counts) {
  if (counts != NULL) {
    *counts = ct_counts;
  }
}
#else
#define CT_COUNT(member) ((void)0)
#endif

static uint32_t ct_mask(uint32_t choice) { return 0u - (choice & 1u); }

static uint32_t ct_u32_is_zero(uint32_t value) {
  return ((value | (0u - value)) >> 31) ^ 1u;
}

/* Keep this materialization out of its caller so ARM emits arithmetic rather
 * than a secret-conditioned IT block for the zero-nonce normalization. */
__attribute__((noinline)) static uint32_t ct_secret_u32_is_zero(
    uint32_t value) {
  return ((value | (0u - value)) >> 31) ^ 1u;
}

static uint32_t ct_fe_is_zero(const ct_fe* a) {
  uint32_t diff = 0;
  for (size_t i = 0; i < CT_LIMBS; i++) {
    diff |= a->v[i];
  }
  return ct_u32_is_zero(diff);
}

static uint32_t ct_fe_equal(const ct_fe* a, const ct_fe* b) {
  uint32_t diff = 0;
  for (size_t i = 0; i < CT_LIMBS; i++) {
    diff |= a->v[i] ^ b->v[i];
  }
  return ct_u32_is_zero(diff);
}

static void ct_fe_select(ct_fe* out, const ct_fe* a, const ct_fe* b,
                         uint32_t choice) {
  const uint32_t mask = ct_mask(choice);
  CT_COUNT(field_select);
  for (size_t i = 0; i < CT_LIMBS; i++) {
    out->v[i] = (a->v[i] & ~mask) | (b->v[i] & mask);
  }
}

static void ct_point_select(ct_point* out, const ct_point* a, const ct_point* b,
                            uint32_t choice) {
  ct_fe_select(&out->x, &a->x, &b->x, choice);
  ct_fe_select(&out->y, &a->y, &b->y, choice);
  ct_fe_select(&out->z, &a->z, &b->z, choice);
}

/* out = a - b. Returns 1 on underflow and 0 otherwise. */
static uint32_t ct_sub_raw(ct_fe* out, const ct_fe* a, const ct_fe* b) {
  uint64_t borrow = 0;
  for (size_t i = 0; i < CT_LIMBS; i++) {
    const uint64_t diff = (uint64_t)a->v[i] - b->v[i] - borrow;
    out->v[i] = (uint32_t)diff;
    borrow = diff >> 63;
  }
  return (uint32_t)borrow;
}

static void ct_add_raw(ct_fe* out, const ct_fe* a, const ct_fe* b) {
  uint64_t carry = 0;
  for (size_t i = 0; i < CT_LIMBS; i++) {
    const uint64_t sum = (uint64_t)a->v[i] + b->v[i] + carry;
    out->v[i] = (uint32_t)sum;
    carry = sum >> 32;
  }
}

static void ct_fe_add_mod(ct_fe* out, const ct_fe* a, const ct_fe* b,
                          const ct_modulus* mod) {
  ct_fe sum;
  ct_fe reduced;
  CT_COUNT(field_add);
  ct_add_raw(&sum, a, b);
  const uint32_t borrow = ct_sub_raw(&reduced, &sum, &mod->modulus);
  ct_fe_select(out, &reduced, &sum, borrow);
}

static void ct_fe_sub_mod(ct_fe* out, const ct_fe* a, const ct_fe* b,
                          const ct_modulus* mod) {
  ct_fe diff;
  ct_fe corrected;
  CT_COUNT(field_sub);
  const uint32_t borrow = ct_sub_raw(&diff, a, b);
  ct_add_raw(&corrected, &diff, &mod->modulus);
  ct_fe_select(out, &diff, &corrected, borrow);
}

/* Return one public-indexed 16-bit half-limb. */
static uint32_t ct_half_limb(const ct_fe* value, size_t index) {
  return (value->v[index / 2] >> ((index & 1u) * 16)) & UINT32_C(0xffff);
}

/*
 * Montgomery multiplication with radix 2^16 and sixteen limbs.
 *
 * Cortex-M3 UMULL/UMLAL instructions have operand-dependent early
 * termination.  Using 16-bit limbs keeps each product-plus-carry at or below
 * UINT32_MAX, so the compiler can use the fixed-latency 32-bit MUL/MLA path.
 * Both Pallas moduli have low half-limb 1, hence -m^-1 mod 2^16 = 0xffff.
 * All carry propagation loops have public, fixed bounds.
 * Requires a < 2^256 and b < mod.  The only unreduced input is paired with a
 * reduced Montgomery constant, so one final conditional subtraction suffices.
 */
static void ct_fe_mul_mod(ct_fe* out, const ct_fe* a, const ct_fe* b,
                          const ct_modulus* mod) {
  enum { CT_HALF_LIMBS = 2 * CT_LIMBS };
  uint16_t t[2 * CT_HALF_LIMBS + 1] = {0};
  CT_COUNT(field_mul);

  for (size_t i = 0; i < CT_HALF_LIMBS; i++) {
    uint32_t carry = 0;
    const uint32_t lhs = ct_half_limb(a, i);
    for (size_t j = 0; j < CT_HALF_LIMBS; j++) {
      const size_t k = i + j;
      const uint32_t accum = lhs * ct_half_limb(b, j) + t[k] + carry;
      t[k] = (uint16_t)accum;
      carry = accum >> 16;
    }
    for (size_t k = i + CT_HALF_LIMBS; k <= 2 * CT_HALF_LIMBS; k++) {
      const uint32_t accum = (uint32_t)t[k] + carry;
      t[k] = (uint16_t)accum;
      carry = accum >> 16;
    }
  }

  for (size_t i = 0; i < CT_HALF_LIMBS; i++) {
    const uint32_t factor = (UINT32_C(0x10000) - t[i]) & UINT32_C(0xffff);
    uint32_t carry = 0;
    for (size_t j = 0; j < CT_HALF_LIMBS; j++) {
      const size_t k = i + j;
      const uint32_t accum =
          factor * ct_half_limb(&mod->modulus, j) + t[k] + carry;
      t[k] = (uint16_t)accum;
      carry = accum >> 16;
    }
    for (size_t k = i + CT_HALF_LIMBS; k <= 2 * CT_HALF_LIMBS; k++) {
      const uint32_t accum = (uint32_t)t[k] + carry;
      t[k] = (uint16_t)accum;
      carry = accum >> 16;
    }
  }

  ct_fe candidate;
  ct_fe reduced;
  for (size_t i = 0; i < CT_LIMBS; i++) {
    candidate.v[i] = (uint32_t)t[2 * (i + CT_LIMBS)] |
                     (uint32_t)t[2 * (i + CT_LIMBS) + 1] << 16;
  }
  const uint32_t borrow = ct_sub_raw(&reduced, &candidate, &mod->modulus);
  ct_fe_select(out, &reduced, &candidate, borrow);
  memzero(t, sizeof(t));
}

static void ct_fe_square_mod(ct_fe* out, const ct_fe* a,
                             const ct_modulus* mod) {
  ct_fe_mul_mod(out, a, a, mod);
}

static void ct_words_from_bn(const bignum256* in, ct_fe* out) {
  memset(out, 0, sizeof(*out));
  for (size_t i = 0; i < BN_LIMBS - 1; i++) {
    const uint64_t value = in->val[i] & BN_LIMB_MASK;
    const size_t bit = i * BN_BITS_PER_LIMB;
    const size_t word = bit / 32;
    const unsigned shift = bit % 32;
    const uint64_t shifted = value << shift;
    out->v[word] |= (uint32_t)shifted;
    out->v[word + 1] |= (uint32_t)(shifted >> 32);
  }
  /* A canonical 256-bit bignum uses only the low 24 bits of limb eight. */
  out->v[CT_LIMBS - 1] |= (in->val[BN_LIMBS - 1] & UINT32_C(0x00ffffff)) << 8;
}

static void ct_words_to_bn(const ct_fe* in, bignum256* out) {
  for (size_t i = 0; i < BN_LIMBS; i++) {
    const size_t bit = i * BN_BITS_PER_LIMB;
    const size_t word = bit / 32;
    const unsigned shift = bit % 32;
    uint64_t pair = in->v[word];
    if (word + 1 < CT_LIMBS) {
      pair |= (uint64_t)in->v[word + 1] << 32;
    }
    out->val[i] = (uint32_t)(pair >> shift) & BN_LIMB_MASK;
  }
}

static void ct_fe_from_bn(ct_fe* out, const bignum256* in,
                          const ct_modulus* mod) {
  ct_fe words;
  ct_words_from_bn(in, &words);
  ct_fe_mul_mod(out, &words, &mod->r2, mod);
  memzero(&words, sizeof(words));
}

static void ct_fe_to_bn(bignum256* out, const ct_fe* in,
                        const ct_modulus* mod) {
  static const ct_fe raw_one = {{1, 0, 0, 0, 0, 0, 0, 0}};
  ct_fe words;
  ct_fe_mul_mod(&words, in, &raw_one, mod);
  ct_words_to_bn(&words, out);
  memzero(&words, sizeof(words));
}

static void ct_fe_inv_p(ct_fe* out, const ct_fe* a) {
  ct_fe result = CT_P.one;
  for (int bit = 254; bit >= 0; bit--) {
    ct_fe squared;
    ct_fe multiplied;
    const uint32_t exponent_bit =
        (CT_P_MINUS_2[(unsigned)bit / 32] >> ((unsigned)bit % 32)) & 1u;
    ct_fe_square_mod(&squared, &result, &CT_P);
    ct_fe_mul_mod(&multiplied, &squared, a, &CT_P);
    ct_fe_select(&result, &squared, &multiplied, exponent_bit);
  }
  *out = result;
}

static void ct_point_identity(ct_point* p) {
  memset(p, 0, sizeof(*p));
  p->y = CT_P.one;
}

static uint32_t ct_point_is_identity(const ct_point* p) {
  return ct_fe_is_zero(&p->z);
}

static void ct_point_from_affine(ct_point* out, const curve_point* in) {
  ct_fe_from_bn(&out->x, &in->x, &CT_P);
  ct_fe_from_bn(&out->y, &in->y, &CT_P);
  const uint32_t identity = ct_fe_is_zero(&out->x) & ct_fe_is_zero(&out->y);
  ct_fe zero = {{0}};
  ct_fe_select(&out->z, &CT_P.one, &zero, identity);
}

static void ct_point_to_affine(curve_point* out, const ct_point* in) {
  const uint32_t identity = ct_point_is_identity(in);
  ct_fe z_inv;
  ct_fe z2;
  ct_fe z3;
  ct_fe x;
  ct_fe y;
  ct_fe zero = {{0}};

  ct_fe_inv_p(&z_inv, &in->z);
  ct_fe_square_mod(&z2, &z_inv, &CT_P);
  ct_fe_mul_mod(&z3, &z2, &z_inv, &CT_P);
  ct_fe_mul_mod(&x, &in->x, &z2, &CT_P);
  ct_fe_mul_mod(&y, &in->y, &z3, &CT_P);
  ct_fe_select(&x, &x, &zero, identity);
  ct_fe_select(&y, &y, &zero, identity);
  ct_fe_to_bn(&out->x, &x, &CT_P);
  ct_fe_to_bn(&out->y, &y, &CT_P);

  memzero(&z_inv, sizeof(z_inv));
  memzero(&z2, sizeof(z2));
  memzero(&z3, sizeof(z3));
  memzero(&x, sizeof(x));
  memzero(&y, sizeof(y));
}

/* Jacobian doubling for y^2 = x^3 + 5 (dbl-2009-l). */
static void ct_point_double(ct_point* out, const ct_point* p) {
  ct_fe a, b, c, d, e, f, t0, t1;
  ct_point result;
  ct_point identity;
  CT_COUNT(point_double);

  ct_fe_square_mod(&a, &p->x, &CT_P);
  ct_fe_square_mod(&b, &p->y, &CT_P);
  ct_fe_square_mod(&c, &b, &CT_P);
  ct_fe_add_mod(&t0, &p->x, &b, &CT_P);
  ct_fe_square_mod(&d, &t0, &CT_P);
  ct_fe_sub_mod(&d, &d, &a, &CT_P);
  ct_fe_sub_mod(&d, &d, &c, &CT_P);
  ct_fe_add_mod(&d, &d, &d, &CT_P);
  ct_fe_add_mod(&e, &a, &a, &CT_P);
  ct_fe_add_mod(&e, &e, &a, &CT_P);
  ct_fe_square_mod(&f, &e, &CT_P);
  ct_fe_mul_mod(&t0, &p->z, &p->y, &CT_P);
  ct_fe_add_mod(&result.z, &t0, &t0, &CT_P);
  ct_fe_add_mod(&t0, &d, &d, &CT_P);
  ct_fe_sub_mod(&result.x, &f, &t0, &CT_P);
  ct_fe_sub_mod(&t0, &d, &result.x, &CT_P);
  ct_fe_mul_mod(&t1, &e, &t0, &CT_P);
  ct_fe_add_mod(&t0, &c, &c, &CT_P);
  ct_fe_add_mod(&t0, &t0, &t0, &CT_P);
  ct_fe_add_mod(&t0, &t0, &t0, &CT_P);
  ct_fe_sub_mod(&result.y, &t1, &t0, &CT_P);

  ct_point_identity(&identity);
  ct_point_select(out, &result, &identity, ct_point_is_identity(p));
}

/*
 * Complete-by-selection Jacobian addition.  The generic formula, doubling,
 * opposite-point result, and identity cases are all computed before masks
 * select the correct result.
 */
static void ct_point_add_internal(ct_point* out, const ct_point* p,
                                  const ct_point* q) {
  ct_fe z1z1, z2z2, u1, u2, s1, s2, h, i, j, r, v, t0, t1;
  ct_point generic;
  ct_point doubled;
  ct_point identity;
  CT_COUNT(point_add);

  ct_fe_square_mod(&z1z1, &p->z, &CT_P);
  ct_fe_square_mod(&z2z2, &q->z, &CT_P);
  ct_fe_mul_mod(&u1, &p->x, &z2z2, &CT_P);
  ct_fe_mul_mod(&u2, &q->x, &z1z1, &CT_P);
  ct_fe_mul_mod(&t0, &z2z2, &q->z, &CT_P);
  ct_fe_mul_mod(&s1, &p->y, &t0, &CT_P);
  ct_fe_mul_mod(&t0, &z1z1, &p->z, &CT_P);
  ct_fe_mul_mod(&s2, &q->y, &t0, &CT_P);

  ct_fe_sub_mod(&h, &u2, &u1, &CT_P);
  ct_fe_add_mod(&t0, &h, &h, &CT_P);
  ct_fe_square_mod(&i, &t0, &CT_P);
  ct_fe_mul_mod(&j, &h, &i, &CT_P);
  ct_fe_sub_mod(&r, &s2, &s1, &CT_P);
  ct_fe_add_mod(&r, &r, &r, &CT_P);
  ct_fe_mul_mod(&v, &u1, &i, &CT_P);
  ct_fe_square_mod(&generic.x, &r, &CT_P);
  ct_fe_sub_mod(&generic.x, &generic.x, &j, &CT_P);
  ct_fe_sub_mod(&generic.x, &generic.x, &v, &CT_P);
  ct_fe_sub_mod(&generic.x, &generic.x, &v, &CT_P);
  ct_fe_sub_mod(&t0, &v, &generic.x, &CT_P);
  ct_fe_mul_mod(&t0, &r, &t0, &CT_P);
  ct_fe_mul_mod(&t1, &s1, &j, &CT_P);
  ct_fe_add_mod(&t1, &t1, &t1, &CT_P);
  ct_fe_sub_mod(&generic.y, &t0, &t1, &CT_P);
  ct_fe_add_mod(&t0, &p->z, &q->z, &CT_P);
  ct_fe_square_mod(&generic.z, &t0, &CT_P);
  ct_fe_sub_mod(&generic.z, &generic.z, &z1z1, &CT_P);
  ct_fe_sub_mod(&generic.z, &generic.z, &z2z2, &CT_P);
  ct_fe_mul_mod(&generic.z, &generic.z, &h, &CT_P);

  ct_point_double(&doubled, p);
  ct_point_identity(&identity);

  const uint32_t p_identity = ct_point_is_identity(p);
  const uint32_t q_identity = ct_point_is_identity(q);
  const uint32_t same_x = ct_fe_equal(&u1, &u2);
  const uint32_t same_y = ct_fe_equal(&s1, &s2);
  const uint32_t neither_identity = (p_identity | q_identity) ^ 1u;
  const uint32_t same = same_x & same_y & neither_identity;
  const uint32_t opposite = same_x & (same_y ^ 1u) & neither_identity;

  *out = generic;
  ct_point_select(out, out, &doubled, same);
  ct_point_select(out, out, &identity, opposite);
  ct_point_select(out, out, q, p_identity);
  ct_point_select(out, out, p, q_identity);
}

void pallas_ct_point_mult(const bignum256* k, const curve_point* p,
                          curve_point* res) {
  ct_fe scalar_mont;
  ct_fe scalar;
  ct_point base;
  ct_point acc;
  static const ct_fe raw_one = {{1, 0, 0, 0, 0, 0, 0, 0}};

  /* Canonicalize k modulo the Pallas group order without a data branch. */
  ct_fe_from_bn(&scalar_mont, k, &CT_Q);
  ct_fe_mul_mod(&scalar, &scalar_mont, &raw_one, &CT_Q);
  ct_point_from_affine(&base, p);
  ct_point_identity(&acc);

  for (int bit = 254; bit >= 0; bit--) {
    ct_point doubled;
    ct_point added;
    const uint32_t scalar_bit =
        (scalar.v[(unsigned)bit / 32] >> ((unsigned)bit % 32)) & 1u;
    CT_COUNT(scalar_round);
    ct_point_double(&doubled, &acc);
    ct_point_add_internal(&added, &doubled, &base);
    ct_point_select(&acc, &doubled, &added, scalar_bit);
  }

  ct_point_to_affine(res, &acc);
  memzero(&scalar_mont, sizeof(scalar_mont));
  memzero(&scalar, sizeof(scalar));
  memzero(&base, sizeof(base));
  memzero(&acc, sizeof(acc));
}

void pallas_ct_point_mult_progress(const bignum256* k, const curve_point* p,
                                   curve_point* res,
                                   pallas_ct_progress_callback progress,
                                   void* progress_context) {
  ct_fe scalar_mont;
  ct_fe scalar;
  ct_point base;
  ct_point acc;
  static const ct_fe raw_one = {{1, 0, 0, 0, 0, 0, 0, 0}};

  /* This is deliberately the same fixed schedule as pallas_ct_point_mult().
   * The callback runs once after every round and receives only public loop
   * counters, so OLED refreshes cannot disclose scalar bits. */
  ct_fe_from_bn(&scalar_mont, k, &CT_Q);
  ct_fe_mul_mod(&scalar, &scalar_mont, &raw_one, &CT_Q);
  ct_point_from_affine(&base, p);
  ct_point_identity(&acc);

  for (int bit = 254; bit >= 0; bit--) {
    ct_point doubled;
    ct_point added;
    const uint32_t scalar_bit =
        (scalar.v[(unsigned)bit / 32] >> ((unsigned)bit % 32)) & 1u;
    CT_COUNT(scalar_round);
    ct_point_double(&doubled, &acc);
    ct_point_add_internal(&added, &doubled, &base);
    ct_point_select(&acc, &doubled, &added, scalar_bit);
    progress((uint32_t)(255 - bit), 255, progress_context);
  }

  ct_point_to_affine(res, &acc);
  memzero(&scalar_mont, sizeof(scalar_mont));
  memzero(&scalar, sizeof(scalar));
  memzero(&base, sizeof(base));
  memzero(&acc, sizeof(acc));
}

void pallas_ct_point_add(const curve_point* p, const curve_point* q,
                         curve_point* res) {
  ct_point lhs;
  ct_point rhs;
  ct_point sum;
  ct_point_from_affine(&lhs, p);
  ct_point_from_affine(&rhs, q);
  ct_point_add_internal(&sum, &lhs, &rhs);
  ct_point_to_affine(res, &sum);
  memzero(&lhs, sizeof(lhs));
  memzero(&rhs, sizeof(rhs));
  memzero(&sum, sizeof(sum));
}

void pallas_ct_mul_mod_p(bignum256* x, const bignum256* k) {
  ct_fe lhs, rhs, result;
  ct_fe_from_bn(&lhs, x, &CT_P);
  ct_fe_from_bn(&rhs, k, &CT_P);
  ct_fe_mul_mod(&result, &lhs, &rhs, &CT_P);
  ct_fe_to_bn(x, &result, &CT_P);
  memzero(&lhs, sizeof(lhs));
  memzero(&rhs, sizeof(rhs));
  memzero(&result, sizeof(result));
}

void pallas_ct_add_mod_p(const bignum256* a, const bignum256* b,
                         bignum256* res) {
  ct_fe lhs, rhs, result;
  ct_fe_from_bn(&lhs, a, &CT_P);
  ct_fe_from_bn(&rhs, b, &CT_P);
  ct_fe_add_mod(&result, &lhs, &rhs, &CT_P);
  ct_fe_to_bn(res, &result, &CT_P);
}

void pallas_ct_sub_mod_p(const bignum256* a, const bignum256* b,
                         bignum256* res) {
  ct_fe lhs, rhs, result;
  ct_fe_from_bn(&lhs, a, &CT_P);
  ct_fe_from_bn(&rhs, b, &CT_P);
  ct_fe_sub_mod(&result, &lhs, &rhs, &CT_P);
  ct_fe_to_bn(res, &result, &CT_P);
}

void pallas_ct_inv_mod_p(bignum256* x) {
  ct_fe value, inverse;
  ct_fe_from_bn(&value, x, &CT_P);
  ct_fe_inv_p(&inverse, &value);
  ct_fe_to_bn(x, &inverse, &CT_P);
  memzero(&value, sizeof(value));
  memzero(&inverse, sizeof(inverse));
}

void pallas_ct_mod_p(bignum256* x) {
  ct_fe value;
  ct_fe_from_bn(&value, x, &CT_P);
  ct_fe_to_bn(x, &value, &CT_P);
  memzero(&value, sizeof(value));
}

void pallas_ct_mul_mod_q(bignum256* x, const bignum256* k) {
  ct_fe lhs, rhs, result;
  ct_fe_from_bn(&lhs, x, &CT_Q);
  ct_fe_from_bn(&rhs, k, &CT_Q);
  ct_fe_mul_mod(&result, &lhs, &rhs, &CT_Q);
  ct_fe_to_bn(x, &result, &CT_Q);
  memzero(&lhs, sizeof(lhs));
  memzero(&rhs, sizeof(rhs));
  memzero(&result, sizeof(result));
}

void pallas_ct_add_mod_q(bignum256* a, const bignum256* b) {
  ct_fe lhs, rhs, result;
  ct_fe_from_bn(&lhs, a, &CT_Q);
  ct_fe_from_bn(&rhs, b, &CT_Q);
  ct_fe_add_mod(&result, &lhs, &rhs, &CT_Q);
  ct_fe_to_bn(a, &result, &CT_Q);
}

void pallas_ct_mod_q(bignum256* x) {
  ct_fe value;
  ct_fe_from_bn(&value, x, &CT_Q);
  ct_fe_to_bn(x, &value, &CT_Q);
  memzero(&value, sizeof(value));
}

void pallas_ct_scalar_replace_zero_with_one(bignum256* scalar) {
  uint32_t nonzero = 0;
  for (size_t i = 0; i < BN_LIMBS; i++) {
    nonzero |= scalar->val[i];
  }
  scalar->val[0] |= ct_secret_u32_is_zero(nonzero);
}
