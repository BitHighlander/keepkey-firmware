/**
 * Copyright (c) 2026 KeepKey
 *
 * Pallas simplified SWU, iso-Pallas isogeny, and hash-to-curve primitives.
 *
 * This follows pasta_curves 0.5.1:
 *   hash_to_field("pallas", domain, msg)
 *   map_to_curve_simple_swu::<Fp, Ep, IsoEp>
 *   iso_map::<Fp, Ep, IsoEp>
 */

#include "pallas_swu.h"

#include <string.h>

#include "memzero.h"
#include "pallas.h"

typedef pallas_jacobian_point iso_point;

static const uint8_t TWO_256_MOD_P[32] = {
    0xfd, 0xff, 0xff, 0xff, 0x38, 0x6d, 0x78, 0x34,
    0xad, 0x14, 0x19, 0xe4, 0x0b, 0x35, 0x2c, 0x99,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
};

static const uint64_t ISO_A_RAW[4] = {
    UINT64_C(0x92bb4b0b657a014b),
    UINT64_C(0xb74134581a27a59f),
    UINT64_C(0x49be2d7258370742),
    UINT64_C(0x18354a2eb0ea8c9c),
};

static const uint64_t ISO_B_RAW[4] = {
    UINT64_C(1265),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
};

static const uint64_t PALLAS_Z_RAW[4] = {
    UINT64_C(0x992d30ecfffffff4),
    UINT64_C(0x224698fc094cf91b),
    UINT64_C(0x0000000000000000),
    UINT64_C(0x4000000000000000),
};

static const uint64_t PALLAS_THETA_RAW[4] = {
    UINT64_C(0xca330bcc09ac318e),
    UINT64_C(0x51f64fc4dc888857),
    UINT64_C(0x4647aef782d5cdc8),
    UINT64_C(0x0f7bdb65814179b4),
};

static const uint64_t PALLAS_ROOT_OF_UNITY_RAW[4] = {
    UINT64_C(0xbdad6fabd87ea32f),
    UINT64_C(0xea322bf2b7bb7584),
    UINT64_C(0x362120830561f81a),
    UINT64_C(0x2bce74deac30ebda),
};

static const uint64_t ISOGENY_RAW[13][4] = {
    {UINT64_C(0x775f6034aaaaaaab), UINT64_C(0x4081775473d8375b),
     UINT64_C(0xe38e38e38e38e38e), UINT64_C(0x0e38e38e38e38e38)},
    {UINT64_C(0x08cf863b02814fb76), UINT64_C(0x0f93b82ee4b99495),
     UINT64_C(0x267c7ffa51cf412a), UINT64_C(0x3509afd51872d88e)},
    {UINT64_C(0x0eb64faef37ea4f7), UINT64_C(0x380af066cfeb6d69),
     UINT64_C(0x98c7d7ac3d98fd13), UINT64_C(0x17329b9ec5253753)},
    {UINT64_C(0xeebec06955555580), UINT64_C(0x8102eea8e7b06eb6),
     UINT64_C(0xc71c71c71c71c71c), UINT64_C(0x1c71c71c71c71c71)},
    {UINT64_C(0xc47f2ab668bcd71f), UINT64_C(0x9c434ac1c96b6980),
     UINT64_C(0x5a607fcce0494a79), UINT64_C(0x1d572e7ddc099cff)},
    {UINT64_C(0x2aa3af1eae5b6604), UINT64_C(0xb4abf9fb9a1fc81c),
     UINT64_C(0x1d13bf2a7f22b105), UINT64_C(0x325669becaecd5d1)},
    {UINT64_C(0x5ad985b5e38e38e4), UINT64_C(0x7642b01ad461bad2),
     UINT64_C(0x4bda12f684bda12f), UINT64_C(0x1a12f684bda12f68)},
    {UINT64_C(0xc67c31d8140a7dbb), UINT64_C(0x07c9dc17725cca4a),
     UINT64_C(0x133e3ffd28e7a095), UINT64_C(0x1a84d7ea8c396c47)},
    {UINT64_C(0x02e2be87d225b234), UINT64_C(0x1765e924f7459378),
     UINT64_C(0x303216cce1db9ff1), UINT64_C(0x3fb98ff0d2ddcadd)},
    {UINT64_C(0x93e53ab371c71c4f), UINT64_C(0x0ac03e8e134eb3e4),
     UINT64_C(0x7b425ed097b425ed), UINT64_C(0x025ed097b425ed09)},
    {UINT64_C(0x5a28279b1d1b42ae), UINT64_C(0x5941a3a4a97aa1b3),
     UINT64_C(0x0790bfb3506defb6), UINT64_C(0x0c02c5bcca0e6b7f)},
    {UINT64_C(0x4d90ab820b12320a), UINT64_C(0xd976bbfabbc5661d),
     UINT64_C(0x573b3d7f7d681310), UINT64_C(0x17033d3c60c68173)},
    {UINT64_C(0x992d30ecfffffde5), UINT64_C(0x224698fc094cf91b),
     UINT64_C(0x0000000000000000), UINT64_C(0x4000000000000000)},
};

static void fp_from_raw_u64(const uint64_t raw[4], bignum256 *out) {
  uint8_t le[32];
  for (int i = 0; i < 4; i++) {
    uint64_t v = raw[i];
    for (int j = 0; j < 8; j++) {
      le[i * 8 + j] = (uint8_t)(v & 0xff);
      v >>= 8;
    }
  }
  bn_read_le(le, out);
  pallas_mod_p(out);
  memzero(le, sizeof(le));
}

static void fp_from_u32(uint32_t v, bignum256 *out) {
  bn_zero(out);
  out->val[0] = v;
  pallas_mod_p(out);
}

static void fp_one(bignum256 *out) { fp_from_u32(1, out); }

static int fp_is_zero(const bignum256 *a) { return bn_is_zero(a); }

static int fp_is_equal(const bignum256 *a, const bignum256 *b) {
  bignum256 aa, bb;
  bn_copy(a, &aa);
  bn_copy(b, &bb);
  bn_normalize(&aa);
  bn_normalize(&bb);
  return bn_is_equal(&aa, &bb);
}

static void fp_add(const bignum256 *a, const bignum256 *b, bignum256 *out) {
  pallas_add_mod_p(a, b, out);
}

static void fp_sub(const bignum256 *a, const bignum256 *b, bignum256 *out) {
  pallas_sub_mod_p(a, b, out);
}

static void fp_neg(const bignum256 *a, bignum256 *out) {
  if (bn_is_zero(a)) {
    bn_zero(out);
  } else {
    pallas_sub_mod_p(&pallas_prime, a, out);
  }
}

static void fp_mul(const bignum256 *a, const bignum256 *b, bignum256 *out) {
  bignum256 aa, bb;
  bn_copy(a, &aa);
  bn_copy(b, &bb);
  pallas_mul_mod_p(&aa, &bb);
  bn_copy(&aa, out);
  memzero(&aa, sizeof(aa));
  memzero(&bb, sizeof(bb));
}

static void fp_square(const bignum256 *a, bignum256 *out) {
  fp_mul(a, a, out);
}

static void fp_double(const bignum256 *a, bignum256 *out) {
  fp_add(a, a, out);
}

static void fp_inv0(const bignum256 *a, bignum256 *out) {
  if (bn_is_zero(a)) {
    bn_zero(out);
  } else {
    bn_copy(a, out);
    pallas_inv_mod_p(out);
  }
}

static int fp_sqrt_ratio(const bignum256 *num, const bignum256 *div,
                         bignum256 *out) {
  bignum256 inv_div, a, candidate;

  if (bn_is_zero(div)) {
    bn_zero(out);
    return bn_is_zero(num);
  }

  fp_inv0(div, &inv_div);
  fp_mul(num, &inv_div, &a);

  bn_copy(&a, &candidate);
  if (pallas_sqrt_mod_p(&candidate) == 0) {
    bn_copy(&candidate, out);
    memzero(&inv_div, sizeof(inv_div));
    memzero(&a, sizeof(a));
    memzero(&candidate, sizeof(candidate));
    return 1;
  }

  bignum256 root_of_unity;
  fp_from_raw_u64(PALLAS_ROOT_OF_UNITY_RAW, &root_of_unity);
  fp_mul(&a, &root_of_unity, &candidate);
  if (pallas_sqrt_mod_p(&candidate) == 0) {
    bn_copy(&candidate, out);
  } else {
    bn_zero(out);
  }

  memzero(&inv_div, sizeof(inv_div));
  memzero(&a, sizeof(a));
  memzero(&candidate, sizeof(candidate));
  memzero(&root_of_unity, sizeof(root_of_unity));
  return 0;
}

static void fp_from_uniform64(const uint8_t in[64], bignum256 *out) {
  bignum256 lo, hi, two_256, tmp;

  bn_read_le(in, &lo);
  pallas_mod_p(&lo);

  bn_read_le(in + 32, &hi);
  pallas_mod_p(&hi);

  bn_read_le(TWO_256_MOD_P, &two_256);

  bn_copy(&hi, &tmp);
  pallas_mul_mod_p(&tmp, &two_256);
  pallas_add_mod_p(&tmp, &lo, out);

  memzero(&lo, sizeof(lo));
  memzero(&hi, sizeof(hi));
  memzero(&two_256, sizeof(two_256));
  memzero(&tmp, sizeof(tmp));
}

static int iso_is_identity(const iso_point *p) {
  return !p || bn_is_zero(&p->z);
}

static void iso_set_identity(iso_point *p) {
  bn_zero(&p->x);
  bn_zero(&p->y);
  bn_zero(&p->z);
}

static int iso_is_on_curve(const iso_point *p) {
  if (iso_is_identity(p)) return 1;

  bignum256 a, b, y2, x2, x3, z2, z4, z6, axz4, bz6, rhs, tmp;
  fp_from_raw_u64(ISO_A_RAW, &a);
  fp_from_raw_u64(ISO_B_RAW, &b);

  fp_square(&p->y, &y2);
  fp_square(&p->x, &x2);
  fp_mul(&x2, &p->x, &x3);
  fp_square(&p->z, &z2);
  fp_square(&z2, &z4);
  fp_mul(&z4, &z2, &z6);
  fp_mul(&a, &p->x, &axz4);
  fp_mul(&axz4, &z4, &axz4);
  fp_mul(&b, &z6, &bz6);
  fp_add(&x3, &axz4, &tmp);
  fp_add(&tmp, &bz6, &rhs);

  int ok = fp_is_equal(&y2, &rhs);
  memzero(&a, sizeof(a));
  memzero(&b, sizeof(b));
  memzero(&y2, sizeof(y2));
  memzero(&x2, sizeof(x2));
  memzero(&x3, sizeof(x3));
  memzero(&z2, sizeof(z2));
  memzero(&z4, sizeof(z4));
  memzero(&z6, sizeof(z6));
  memzero(&axz4, sizeof(axz4));
  memzero(&bz6, sizeof(bz6));
  memzero(&rhs, sizeof(rhs));
  memzero(&tmp, sizeof(tmp));
  return ok;
}

static void iso_double(const iso_point *p, iso_point *out) {
  if (iso_is_identity(p)) {
    iso_set_identity(out);
    return;
  }

  bignum256 curve_a;
  fp_from_raw_u64(ISO_A_RAW, &curve_a);

  bignum256 xx, yy, yyyy, zz, s, m, x3, y3, z3, tmp1, tmp2;
  fp_square(&p->x, &xx);
  fp_square(&p->y, &yy);
  fp_square(&yy, &yyyy);
  fp_square(&p->z, &zz);

  fp_add(&p->x, &yy, &tmp1);
  fp_square(&tmp1, &tmp1);
  fp_sub(&tmp1, &xx, &tmp1);
  fp_sub(&tmp1, &yyyy, &tmp1);
  fp_double(&tmp1, &s);

  fp_double(&xx, &tmp1);
  fp_add(&tmp1, &xx, &m);
  fp_square(&zz, &tmp1);
  fp_mul(&curve_a, &tmp1, &tmp1);
  fp_add(&m, &tmp1, &m);

  fp_square(&m, &x3);
  fp_double(&s, &tmp1);
  fp_sub(&x3, &tmp1, &x3);

  fp_sub(&s, &x3, &tmp1);
  fp_mul(&m, &tmp1, &y3);
  fp_double(&yyyy, &tmp2);
  fp_double(&tmp2, &tmp2);
  fp_double(&tmp2, &tmp2);
  fp_sub(&y3, &tmp2, &y3);

  fp_add(&p->y, &p->z, &z3);
  fp_square(&z3, &z3);
  fp_sub(&z3, &yy, &z3);
  fp_sub(&z3, &zz, &z3);

  bn_copy(&x3, &out->x);
  bn_copy(&y3, &out->y);
  bn_copy(&z3, &out->z);

  memzero(&curve_a, sizeof(curve_a));
  memzero(&xx, sizeof(xx));
  memzero(&yy, sizeof(yy));
  memzero(&yyyy, sizeof(yyyy));
  memzero(&zz, sizeof(zz));
  memzero(&s, sizeof(s));
  memzero(&m, sizeof(m));
  memzero(&x3, sizeof(x3));
  memzero(&y3, sizeof(y3));
  memzero(&z3, sizeof(z3));
  memzero(&tmp1, sizeof(tmp1));
  memzero(&tmp2, sizeof(tmp2));
}

static void iso_add(const iso_point *p, const iso_point *q, iso_point *out) {
  if (iso_is_identity(p)) {
    *out = *q;
    return;
  }
  if (iso_is_identity(q)) {
    *out = *p;
    return;
  }

  bignum256 z1z1, z2z2, u1, u2, s1, s2, h, i, j, r, v;
  bignum256 x3, y3, z3;

  fp_square(&p->z, &z1z1);
  fp_square(&q->z, &z2z2);
  fp_mul(&p->x, &z2z2, &u1);
  fp_mul(&q->x, &z1z1, &u2);
  fp_mul(&p->y, &z2z2, &s1);
  fp_mul(&s1, &q->z, &s1);
  fp_mul(&q->y, &z1z1, &s2);
  fp_mul(&s2, &p->z, &s2);

  if (fp_is_equal(&u1, &u2)) {
    if (fp_is_equal(&s1, &s2)) {
      iso_double(p, out);
    } else {
      iso_set_identity(out);
    }
    return;
  }

  fp_sub(&u2, &u1, &h);
  fp_double(&h, &i);
  fp_square(&i, &i);
  fp_mul(&h, &i, &j);
  fp_sub(&s2, &s1, &r);
  fp_double(&r, &r);
  fp_mul(&u1, &i, &v);

  fp_square(&r, &x3);
  fp_sub(&x3, &j, &x3);
  fp_sub(&x3, &v, &x3);
  fp_sub(&x3, &v, &x3);

  fp_mul(&s1, &j, &s1);
  fp_double(&s1, &s1);
  fp_sub(&v, &x3, &y3);
  fp_mul(&r, &y3, &y3);
  fp_sub(&y3, &s1, &y3);

  fp_add(&p->z, &q->z, &z3);
  fp_square(&z3, &z3);
  fp_sub(&z3, &z1z1, &z3);
  fp_sub(&z3, &z2z2, &z3);
  fp_mul(&z3, &h, &z3);

  bn_copy(&x3, &out->x);
  bn_copy(&y3, &out->y);
  bn_copy(&z3, &out->z);

  memzero(&z1z1, sizeof(z1z1));
  memzero(&z2z2, sizeof(z2z2));
  memzero(&u1, sizeof(u1));
  memzero(&u2, sizeof(u2));
  memzero(&s1, sizeof(s1));
  memzero(&s2, sizeof(s2));
  memzero(&h, sizeof(h));
  memzero(&i, sizeof(i));
  memzero(&j, sizeof(j));
  memzero(&r, sizeof(r));
  memzero(&v, sizeof(v));
  memzero(&x3, sizeof(x3));
  memzero(&y3, sizeof(y3));
  memzero(&z3, sizeof(z3));
}

int pallas_map_to_curve_simple_swu(const uint8_t u_le[32],
                                   pallas_jacobian_point *out) {
  if (!u_le || !out) return -1;

  bignum256 u, a, b, z, theta, one;
  bignum256 u2, z_u2, ta, num_x1, div, num2_x1, div2, div3;
  bignum256 num_gx1, num_x2, y1, y2, num_x, y, tmp1, tmp2;

  bn_read_le(u_le, &u);
  pallas_mod_p(&u);
  fp_from_raw_u64(ISO_A_RAW, &a);
  fp_from_raw_u64(ISO_B_RAW, &b);
  fp_from_raw_u64(PALLAS_Z_RAW, &z);
  fp_from_raw_u64(PALLAS_THETA_RAW, &theta);
  fp_one(&one);

  fp_square(&u, &u2);
  fp_mul(&z, &u2, &z_u2);
  fp_square(&z_u2, &ta);
  fp_add(&ta, &z_u2, &ta);

  fp_add(&ta, &one, &tmp1);
  fp_mul(&b, &tmp1, &num_x1);

  if (fp_is_zero(&ta)) {
    bn_copy(&z, &tmp1);
  } else {
    fp_neg(&ta, &tmp1);
  }
  fp_mul(&a, &tmp1, &div);

  fp_square(&num_x1, &num2_x1);
  fp_square(&div, &div2);
  fp_mul(&div2, &div, &div3);
  fp_mul(&a, &div2, &tmp1);
  fp_add(&num2_x1, &tmp1, &tmp1);
  fp_mul(&tmp1, &num_x1, &tmp1);
  fp_mul(&b, &div3, &tmp2);
  fp_add(&tmp1, &tmp2, &num_gx1);

  fp_mul(&z_u2, &num_x1, &num_x2);

  int gx1_square = fp_sqrt_ratio(&num_gx1, &div3, &y1);

  fp_mul(&theta, &z_u2, &y2);
  fp_mul(&y2, &u, &y2);
  fp_mul(&y2, &y1, &y2);

  if (gx1_square) {
    bn_copy(&num_x1, &num_x);
    bn_copy(&y1, &y);
  } else {
    bn_copy(&num_x2, &num_x);
    bn_copy(&y2, &y);
  }

  if (bn_is_odd(&u) != bn_is_odd(&y)) {
    fp_neg(&y, &y);
  }

  fp_mul(&num_x, &div, &out->x);
  fp_mul(&y, &div3, &out->y);
  bn_copy(&div, &out->z);

  int ok = iso_is_on_curve(out);

  memzero(&u, sizeof(u));
  memzero(&a, sizeof(a));
  memzero(&b, sizeof(b));
  memzero(&z, sizeof(z));
  memzero(&theta, sizeof(theta));
  memzero(&one, sizeof(one));
  memzero(&u2, sizeof(u2));
  memzero(&z_u2, sizeof(z_u2));
  memzero(&ta, sizeof(ta));
  memzero(&num_x1, sizeof(num_x1));
  memzero(&div, sizeof(div));
  memzero(&num2_x1, sizeof(num2_x1));
  memzero(&div2, sizeof(div2));
  memzero(&div3, sizeof(div3));
  memzero(&num_gx1, sizeof(num_gx1));
  memzero(&num_x2, sizeof(num_x2));
  memzero(&y1, sizeof(y1));
  memzero(&y2, sizeof(y2));
  memzero(&num_x, sizeof(num_x));
  memzero(&y, sizeof(y));
  memzero(&tmp1, sizeof(tmp1));
  memzero(&tmp2, sizeof(tmp2));

  return ok ? 0 : -1;
}

static void pallas_projective_to_affine(const bignum256 *x, const bignum256 *y,
                                        const bignum256 *z, curve_point *out) {
  if (bn_is_zero(z)) {
    bn_zero(&out->x);
    bn_zero(&out->y);
    return;
  }

  bignum256 z_inv, z_inv2, z_inv3;
  bn_copy(z, &z_inv);
  pallas_inv_mod_p(&z_inv);
  fp_square(&z_inv, &z_inv2);
  fp_mul(&z_inv2, &z_inv, &z_inv3);
  fp_mul(x, &z_inv2, &out->x);
  fp_mul(y, &z_inv3, &out->y);

  memzero(&z_inv, sizeof(z_inv));
  memzero(&z_inv2, sizeof(z_inv2));
  memzero(&z_inv3, sizeof(z_inv3));
}

static int pallas_point_on_curve(const curve_point *p) {
  if (pallas_point_is_identity(p)) return 1;

  bignum256 y2, x2, x3, five, rhs;
  fp_square(&p->y, &y2);
  fp_square(&p->x, &x2);
  fp_mul(&x2, &p->x, &x3);
  fp_from_u32(5, &five);
  fp_add(&x3, &five, &rhs);
  int ok = fp_is_equal(&y2, &rhs);
  memzero(&y2, sizeof(y2));
  memzero(&x2, sizeof(x2));
  memzero(&x3, sizeof(x3));
  memzero(&five, sizeof(five));
  memzero(&rhs, sizeof(rhs));
  return ok;
}

int pallas_iso_map_to_pallas(const pallas_jacobian_point *iso,
                             curve_point *out) {
  if (!iso || !out) return -1;
  if (iso_is_identity(iso)) {
    bn_zero(&out->x);
    bn_zero(&out->y);
    return 0;
  }

  bignum256 c[13];
  for (int i = 0; i < 13; i++) {
    fp_from_raw_u64(ISOGENY_RAW[i], &c[i]);
  }

  bignum256 z2, z3, z4, z6, num_x, div_x, num_y, div_y;
  bignum256 zo, xo, yo, tmp1, tmp2, tmp3;

  fp_square(&iso->z, &z2);
  fp_mul(&z2, &iso->z, &z3);
  fp_square(&z2, &z4);
  fp_square(&z3, &z6);

  fp_mul(&c[0], &iso->x, &tmp1);
  fp_mul(&c[1], &z2, &tmp2);
  fp_add(&tmp1, &tmp2, &tmp1);
  fp_mul(&tmp1, &iso->x, &tmp1);
  fp_mul(&c[2], &z4, &tmp2);
  fp_add(&tmp1, &tmp2, &tmp1);
  fp_mul(&tmp1, &iso->x, &tmp1);
  fp_mul(&c[3], &z6, &tmp2);
  fp_add(&tmp1, &tmp2, &num_x);

  fp_mul(&z2, &iso->x, &tmp1);
  fp_mul(&c[4], &z4, &tmp2);
  fp_add(&tmp1, &tmp2, &tmp1);
  fp_mul(&tmp1, &iso->x, &tmp1);
  fp_mul(&c[5], &z6, &tmp2);
  fp_add(&tmp1, &tmp2, &div_x);

  fp_mul(&c[6], &iso->x, &tmp1);
  fp_mul(&c[7], &z2, &tmp2);
  fp_add(&tmp1, &tmp2, &tmp1);
  fp_mul(&tmp1, &iso->x, &tmp1);
  fp_mul(&c[8], &z4, &tmp2);
  fp_add(&tmp1, &tmp2, &tmp1);
  fp_mul(&tmp1, &iso->x, &tmp1);
  fp_mul(&c[9], &z6, &tmp2);
  fp_add(&tmp1, &tmp2, &tmp1);
  fp_mul(&tmp1, &iso->y, &num_y);

  fp_mul(&c[10], &z2, &tmp1);
  fp_add(&iso->x, &tmp1, &tmp1);
  fp_mul(&tmp1, &iso->x, &tmp1);
  fp_mul(&c[11], &z4, &tmp2);
  fp_add(&tmp1, &tmp2, &tmp1);
  fp_mul(&tmp1, &iso->x, &tmp1);
  fp_mul(&c[12], &z6, &tmp2);
  fp_add(&tmp1, &tmp2, &tmp1);
  fp_mul(&tmp1, &z3, &div_y);

  fp_mul(&div_x, &div_y, &zo);
  fp_mul(&num_x, &div_y, &xo);
  fp_mul(&xo, &zo, &xo);
  fp_mul(&num_y, &div_x, &yo);
  fp_square(&zo, &tmp3);
  fp_mul(&yo, &tmp3, &yo);

  pallas_projective_to_affine(&xo, &yo, &zo, out);
  int ok = pallas_point_on_curve(out);

  for (int i = 0; i < 13; i++) {
    memzero(&c[i], sizeof(c[i]));
  }
  memzero(&z2, sizeof(z2));
  memzero(&z3, sizeof(z3));
  memzero(&z4, sizeof(z4));
  memzero(&z6, sizeof(z6));
  memzero(&num_x, sizeof(num_x));
  memzero(&div_x, sizeof(div_x));
  memzero(&num_y, sizeof(num_y));
  memzero(&div_y, sizeof(div_y));
  memzero(&zo, sizeof(zo));
  memzero(&xo, sizeof(xo));
  memzero(&yo, sizeof(yo));
  memzero(&tmp1, sizeof(tmp1));
  memzero(&tmp2, sizeof(tmp2));
  memzero(&tmp3, sizeof(tmp3));

  return ok ? 0 : -1;
}

static int hash_to_field(const char *domain_prefix, const uint8_t *msg,
                         size_t msg_len, bignum256 out[2]) {
  static const char curve_id[] = "pallas";
  static const char suffix[] = "_XMD:BLAKE2b_SSWU_RO_";

  if (!domain_prefix || (!msg && msg_len != 0) || !out) return -1;

  size_t domain_len = strlen(domain_prefix);
  size_t curve_len = sizeof(curve_id) - 1;
  size_t suffix_len = sizeof(suffix) - 1;
  size_t dst_len = domain_len + 1 + curve_len + suffix_len;
  if (domain_len >= 256 || dst_len >= 256) return -1;

  uint8_t dst[255];
  uint8_t uniform[128];
  uint8_t le[64];

  memcpy(dst, domain_prefix, domain_len);
  dst[domain_len] = '-';
  memcpy(dst + domain_len + 1, curve_id, curve_len);
  memcpy(dst + domain_len + 1 + curve_len, suffix, suffix_len);

  if (pallas_expand_message_xmd_blake2b(msg, msg_len, dst, dst_len, uniform,
                                        sizeof(uniform)) != 0) {
    memzero(dst, sizeof(dst));
    return -1;
  }

  for (int i = 0; i < 2; i++) {
    for (int j = 0; j < 64; j++) {
      le[j] = uniform[i * 64 + (63 - j)];
    }
    fp_from_uniform64(le, &out[i]);
  }

  memzero(dst, sizeof(dst));
  memzero(uniform, sizeof(uniform));
  memzero(le, sizeof(le));
  return 0;
}

int pallas_hash_to_curve(const char *domain_prefix, const uint8_t *msg,
                         size_t msg_len, curve_point *out) {
  if (!domain_prefix || (!msg && msg_len != 0) || !out) return -1;

  bignum256 u[2];
  iso_point q0, q1, r;
  uint8_t u_le[32];

  if (hash_to_field(domain_prefix, msg, msg_len, u) != 0) {
    return -1;
  }

  bn_write_le(&u[0], u_le);
  if (pallas_map_to_curve_simple_swu(u_le, &q0) != 0) {
    memzero(u, sizeof(u));
    memzero(u_le, sizeof(u_le));
    return -1;
  }

  bn_write_le(&u[1], u_le);
  if (pallas_map_to_curve_simple_swu(u_le, &q1) != 0) {
    memzero(u, sizeof(u));
    memzero(u_le, sizeof(u_le));
    memzero(&q0, sizeof(q0));
    return -1;
  }

  iso_add(&q0, &q1, &r);
  int ret = pallas_iso_map_to_pallas(&r, out);

  memzero(u, sizeof(u));
  memzero(u_le, sizeof(u_le));
  memzero(&q0, sizeof(q0));
  memzero(&q1, sizeof(q1));
  memzero(&r, sizeof(r));
  return ret;
}

int pallas_group_hash(const char *domain_prefix, const uint8_t *msg,
                      size_t msg_len, curve_point *out) {
  return pallas_hash_to_curve(domain_prefix, msg, msg_len, out);
}
