/**
 * Copyright (c) 2026 KeepKey
 *
 * Minimal Sinsemilla short-commit implementation for Orchard IVK derivation.
 *
 * This intentionally implements only:
 *   Commit^ivk.Output = SinsemillaShortCommit(
 *       "z.cash:Orchard-CommitIvk", ak || nk, rivk)
 *
 * S generators are derived on demand with the upstream
 * "z.cash:SinsemillaS" hash-to-curve personalization. This keeps firmware
 * ROM usage low by avoiding the 64 KiB precomputed generator table.
 */

#include "pallas_sinsemilla.h"

#include <stddef.h>
#include <string.h>

#include "bignum.h"
#include "memzero.h"
#include "pallas.h"
#include "pallas_swu.h"

static const uint8_t COMMIT_IVK_Q_X[32] = {
    0xf2, 0x82, 0x0f, 0x79, 0x92, 0x2f, 0xcb, 0x6b,
    0x32, 0xa2, 0x28, 0x51, 0x24, 0xcc, 0x1b, 0x42,
    0xfa, 0x41, 0xa2, 0x5a, 0xb8, 0x81, 0xcc, 0x7d,
    0x11, 0xc8, 0xa9, 0x4a, 0xf1, 0x0c, 0xbc, 0x05,
};

static const uint8_t COMMIT_IVK_Q_Y[32] = {
    0xbe, 0xde, 0xad, 0xcf, 0xce, 0xe5, 0x5a, 0xbe,
    0xf1, 0xa5, 0x6d, 0xc9, 0x1d, 0x35, 0xc4, 0x46,
    0x4b, 0x05, 0xde, 0x20, 0x46, 0x07, 0x59, 0xef,
    0xe6, 0xbe, 0x1a, 0xd4, 0xf6, 0x4c, 0x01, 0x1b,
};

static const uint8_t COMMIT_IVK_R_X[32] = {
    0x18, 0xa1, 0xf8, 0x5f, 0x6e, 0x48, 0x23, 0x98,
    0xc7, 0xed, 0x1a, 0xd3, 0xe2, 0x7f, 0x95, 0x02,
    0x48, 0x89, 0x80, 0x40, 0x0a, 0x29, 0x34, 0x16,
    0x4e, 0x13, 0x70, 0x50, 0xcd, 0x2c, 0xa2, 0x25,
};

static const uint8_t COMMIT_IVK_R_Y[32] = {
    0xa9, 0xdd, 0x7f, 0xe3, 0xb3, 0x93, 0xe7, 0x3f,
    0xc7, 0xa6, 0x58, 0x1b, 0xfb, 0x42, 0x44, 0x6b,
    0x94, 0x57, 0x4b, 0x28, 0xc4, 0x90, 0xc8, 0xc2,
    0xeb, 0xfa, 0xa2, 0x66, 0x99, 0xd2, 0xcf, 0x29,
};

static void point_from_xy_le(const uint8_t x[32], const uint8_t y[32],
                             curve_point *out) {
  bn_read_le(x, &out->x);
  bn_read_le(y, &out->y);
  bn_normalize(&out->x);
  bn_normalize(&out->y);
}

static int read_base_field(const uint8_t in[32], bignum256 *out) {
  if (!in || !out) return -1;
  bn_read_le(in, out);
  bn_normalize(out);
  return bn_is_less(out, &pallas_prime) ? 0 : -1;
}

static int read_scalar_field(const uint8_t in[32], bignum256 *out) {
  if (!in || !out) return -1;
  bn_read_le(in, out);
  bn_normalize(out);
  return bn_is_less(out, &pallas_order) ? 0 : -1;
}

static int points_same_x(const curve_point *a, const curve_point *b) {
  bignum256 ax, bx;
  bn_copy(&a->x, &ax);
  bn_copy(&b->x, &bx);
  bn_normalize(&ax);
  bn_normalize(&bx);
  int same = bn_is_equal(&ax, &bx);
  memzero(&ax, sizeof(ax));
  memzero(&bx, sizeof(bx));
  return same;
}

static int sinsemilla_incomplete_add(const curve_point *a, const curve_point *b,
                                     curve_point *out) {
  if (!a || !b || !out) return -1;
  if (pallas_point_is_identity(a) || pallas_point_is_identity(b)) return -1;
  if (points_same_x(a, b)) return -1;

  pallas_point_add(a, b, out);
  return 0;
}

static int bit_from_msg(const uint8_t *msg, size_t bit) {
  return (msg[bit / 8] >> (bit % 8)) & 1;
}

static uint32_t sinsemilla_word(const uint8_t *msg, size_t msg_bits,
                                size_t word_idx) {
  uint32_t word = 0;
  for (size_t i = 0; i < PALLAS_SINSEMILLA_K; i++) {
    size_t bit = word_idx * PALLAS_SINSEMILLA_K + i;
    if (bit < msg_bits && bit_from_msg(msg, bit)) {
      word |= (uint32_t)1 << i;
    }
  }
  return word;
}

static int sinsemilla_s_generator(uint32_t word, curve_point *out) {
  static const char domain[] = "z.cash:SinsemillaS";
  uint8_t word_le[4] = {
      (uint8_t)(word & 0xff),
      (uint8_t)((word >> 8) & 0xff),
      (uint8_t)((word >> 16) & 0xff),
      (uint8_t)((word >> 24) & 0xff),
  };
  int ret = pallas_hash_to_curve(domain, word_le, sizeof(word_le), out);
  memzero(word_le, sizeof(word_le));
  return ret;
}

static void set_msg_bit(uint8_t *msg, size_t bit) {
  msg[bit / 8] |= (uint8_t)(1u << (bit % 8));
}

static void pack_commit_ivk_msg(const uint8_t ak[32], const uint8_t nk[32],
                                uint8_t msg[64]) {
  memset(msg, 0, 64);
  for (size_t bit = 0; bit < 255; bit++) {
    if (bit_from_msg(ak, bit)) {
      set_msg_bit(msg, bit);
    }
    if (bit_from_msg(nk, bit)) {
      set_msg_bit(msg, 255 + bit);
    }
  }
}

int pallas_sinsemilla_hash_to_point(const curve_point *q, const uint8_t *msg,
                                    size_t msg_bits, curve_point *out) {
  if (!q || (!msg && msg_bits != 0) || !out) return -1;
  if (msg_bits > PALLAS_SINSEMILLA_MAX_BITS) return -1;
  if (pallas_point_is_identity(q)) return -1;

  curve_point acc = *q;
  size_t word_count =
      (msg_bits + PALLAS_SINSEMILLA_K - 1) / PALLAS_SINSEMILLA_K;

  for (size_t i = 0; i < word_count; i++) {
    uint32_t word = sinsemilla_word(msg, msg_bits, i);
    curve_point s, old_acc, tmp;
    if (sinsemilla_s_generator(word, &s) != 0) {
      memzero(&acc, sizeof(acc));
      return -1;
    }
    old_acc = acc;

    if (sinsemilla_incomplete_add(&old_acc, &s, &tmp) != 0 ||
        sinsemilla_incomplete_add(&tmp, &old_acc, &acc) != 0) {
      memzero(&acc, sizeof(acc));
      memzero(&s, sizeof(s));
      memzero(&old_acc, sizeof(old_acc));
      memzero(&tmp, sizeof(tmp));
      return -1;
    }

    memzero(&s, sizeof(s));
    memzero(&old_acc, sizeof(old_acc));
    memzero(&tmp, sizeof(tmp));
  }

  *out = acc;
  memzero(&acc, sizeof(acc));
  return 0;
}

int pallas_sinsemilla_hash(const curve_point *q, const uint8_t *msg,
                           size_t msg_bits, uint8_t hash_out[32]) {
  if (!hash_out) return -1;

  curve_point hash_point;
  if (pallas_sinsemilla_hash_to_point(q, msg, msg_bits, &hash_point) != 0) {
    return -1;
  }

  bignum256 x;
  bn_copy(&hash_point.x, &x);
  bn_write_le(&x, hash_out);

  memzero(&hash_point, sizeof(hash_point));
  memzero(&x, sizeof(x));
  return 0;
}

int pallas_sinsemilla_commit(const curve_point *q, const curve_point *r,
                             const uint8_t *msg, size_t msg_bits,
                             const uint8_t blind[32], curve_point *out) {
  if (!r || !blind || !out) return -1;
  if (pallas_point_is_identity(r)) return -1;

  bignum256 blind_scalar;
  if (read_scalar_field(blind, &blind_scalar) != 0) {
    memzero(&blind_scalar, sizeof(blind_scalar));
    return -1;
  }

  curve_point hash_point, blind_point, commit;
  if (pallas_sinsemilla_hash_to_point(q, msg, msg_bits, &hash_point) != 0) {
    memzero(&blind_scalar, sizeof(blind_scalar));
    return -1;
  }

  pallas_point_mult(&blind_scalar, r, &blind_point);
  pallas_point_add(&hash_point, &blind_point, &commit);
  *out = commit;

  memzero(&blind_scalar, sizeof(blind_scalar));
  memzero(&hash_point, sizeof(hash_point));
  memzero(&blind_point, sizeof(blind_point));
  memzero(&commit, sizeof(commit));
  return 0;
}

int pallas_sinsemilla_short_commit(const curve_point *q, const curve_point *r,
                                   const uint8_t *msg, size_t msg_bits,
                                   const uint8_t blind[32],
                                   uint8_t out[32]) {
  if (!out) return -1;

  curve_point commit;
  if (pallas_sinsemilla_commit(q, r, msg, msg_bits, blind, &commit) != 0) {
    return -1;
  }

  bignum256 x;
  bn_copy(&commit.x, &x);
  bn_write_le(&x, out);

  memzero(&commit, sizeof(commit));
  memzero(&x, sizeof(x));
  return 0;
}

int pallas_sinsemilla_commit_ivk(const uint8_t ak[32], const uint8_t nk[32],
                                 const uint8_t rivk[32],
                                 uint8_t ivk_out[32]) {
  if (!ak || !nk || !rivk || !ivk_out) return -1;

  bignum256 ak_field, nk_field;
  if (read_base_field(ak, &ak_field) != 0 ||
      read_base_field(nk, &nk_field) != 0) {
    memzero(&ak_field, sizeof(ak_field));
    memzero(&nk_field, sizeof(nk_field));
    return -1;
  }

  uint8_t msg[64];
  curve_point q, r;
  pack_commit_ivk_msg(ak, nk, msg);
  point_from_xy_le(COMMIT_IVK_Q_X, COMMIT_IVK_Q_Y, &q);
  point_from_xy_le(COMMIT_IVK_R_X, COMMIT_IVK_R_Y, &r);
  int ret = pallas_sinsemilla_short_commit(&q, &r, msg, 510, rivk, ivk_out);

  memzero(&ak_field, sizeof(ak_field));
  memzero(&nk_field, sizeof(nk_field));
  memzero(msg, sizeof(msg));
  memzero(&q, sizeof(q));
  memzero(&r, sizeof(r));
  return ret;
}
