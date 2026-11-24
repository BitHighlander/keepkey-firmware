/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Bulletproofs+ prover for 1 or 2 outputs. Same transcript and same proof as
 * Monero Core v0.18.5.4 bulletproof_plus_PROVE (src/ringct/
 * bulletproofs_plus.cc), on a schedule that fits 128 KB of SRAM:
 *
 *  - aL, aR, d, the y powers, a' and b' are never stored. Every round
 *    recomputes the entries it needs from the amount bits and the stored
 *    round challenges (eval_ab).
 *  - Gi and Hi are derived on demand by hash_to_ec; there is no table.
 *  - From round 1 on only the folded G' and H' are kept, packed, in the
 *    caller's workspace (2 * 64 * 32 B for 2 outputs).
 *  - Every multiexp with a witness-dependent scalar (A, L, R, A1, B, V) is
 *    constant time. Folding the generators uses public challenges and public
 *    points only and is variable time.
 */

#include <string.h>

#include "crypto_internal.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/monero/serialize.h"
#include "trezor/crypto/monero/xmr.h"

_Static_assert(sizeof(xmr_bpp_workspace) == XMR_BPP_WORKSPACE_BYTES,
               "update XMR_BPP_WORKSPACE_BYTES and the signer's arena plan");
_Static_assert(XMR_BPP_WORKSPACE_BYTES <= XMR_FRAME_ARENA_FLOOR_BYTES,
               "the BP+ workspace must fit the ARM frame arena");
_Static_assert(XMR_BPP_SERIALIZED_MAX == 642, "Core layout for 2 outputs");

#define BPP_HEDGE_DOMAIN "KKXMR-bpp-v1"

/* Monero H, packed. */
static const uint8_t H_PACKED[32] = {
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc,
    0x9f, 0xf1, 0xad, 0xd0, 0xea, 0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54,
    0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94};
/* hash_to_p3(keccak("bulletproof_plus_transcript")), packed (Core
 * init_exponents). */
static const uint8_t INITIAL_TRANSCRIPT[32] = {
    0x4a, 0x67, 0x7c, 0x90, 0xeb, 0x73, 0x05, 0x1e, 0x79, 0x0d, 0xa4,
    0x55, 0x91, 0x10, 0x7f, 0x6e, 0xe1, 0x05, 0x90, 0x4d, 0x91, 0x87,
    0xc5, 0xd3, 0x54, 0x71, 0x09, 0x6c, 0x44, 0x5a, 0x22, 0x75};

typedef struct {
  size_t m, M, MN, logMN;
  const uint64_t *amounts;
  bignum256modm y, yinv, z, inv8, z2pow[XMR_BPP_MAX_OUTPUTS];
  bignum256modm ypw[XMR_BPP_MAX_ROUNDS + 1], yinvpw[XMR_BPP_MAX_ROUNDS + 1];
  /* per round: a' = e*a_lo + ka*a_hi, b' = einv*b_lo + e*b_hi */
  bignum256modm ch_e[XMR_BPP_MAX_ROUNDS], ch_einv[XMR_BPP_MAX_ROUNDS],
      ch_ka[XMR_BPP_MAX_ROUNDS];
  uint8_t nk[32]; /* hedge key */
  xmr_bpp_workspace *ws;
  xmr_progress_fn progress;
  void *progress_ctx;
  uint32_t done, total;
} bpp_ctx;

typedef enum { BPP_OK = 0, BPP_FAIL, BPP_ABORTED } bpp_rc;

/* Progress point. Only called where the workspace holds no secret. */
static bool step(bpp_ctx *c) {
  c->done++;
  return c->progress == NULL || c->progress(c->progress_ctx, c->done, c->total);
}

/* transcript = H(transcript || a [|| b]) mod l (public data) */
static void transcript_update(uint8_t T[32], const uint8_t *a,
                              const uint8_t *b) {
  uint8_t buf[96];
  bignum256modm t;
  memcpy(buf, T, 32);
  memcpy(buf + 32, a, 32);
  if (b) memcpy(buf + 64, b, 32);
  xmr_hash_to_scalar(t, buf, b ? 96 : 64);
  contract256_modm(T, t);
}

static void ge_base(ge25519 *r, const bignum256modm s) {
  ge25519_scalarmult_base_niels(r, ge25519_niels_base_multiples, s);
}

static void ge_cmov(ge25519 *r, const ge25519 *p, uint32_t flag) {
  uint32_t mask = (uint32_t)0 - flag;
  /* Keep the secret mask opaque to the optimizer, including under LTO. */
  __asm__ volatile("" : "+r"(mask));
  uint8_t *dst = (uint8_t *)r;
  const uint8_t *src = (const uint8_t *)p;
  for (size_t i = 0; i < sizeof(*r); i++)
    dst[i] ^= (uint8_t)mask & (dst[i] ^ src[i]);
}

/* Gi (is_h = 0) or Hi (is_h = 1): hash_to_ec(H || "bulletproof_plus" ||
 * varint(2i + !is_h)), as Core's get_exponent. */
static void generator(ge25519 *P, int is_h, size_t i) {
  uint8_t buf[32 + 16 + 10], h[32];
  memcpy(buf, H_PACKED, 32);
  memcpy(buf + 32, "bulletproof_plus", 16);
  int n = xmr_write_varint(buf + 48, 10, is_h ? 2 * i : 2 * i + 1);
  keccak_256(buf, 48 + (size_t)n, h);
  xmr_hash_to_ec(P, h, 32);
}

/* Constant-time multiexp, acc += sum s_k * P_k for up to XMR_MSM_CT_POINTS
 * terms: 4-bit signed fixed windows as ge25519_scalarmult, one doubling chain.
 * Every batch is flushed within the loop iteration that filled it, so the
 * pending slots point at the caller's points. */
typedef struct {
  int cnt;
  const ge25519 *P[XMR_MSM_CT_POINTS];
  bignum256modm s[XMR_MSM_CT_POINTS];
} msm_pending;

static void __attribute__((noinline)) msm_flush(xmr_msm_ct_tables *w,
                                                ge25519 *acc, msm_pending *m) {
  ge25519_pniels pre;
  ge25519 r, d1;
  ge25519_p1p1 t;
  if (!m->cnt) return;
  for (int k = 0; k < m->cnt; k++) {
    contract256_window4_modm(w->digits[k], m->s[k]);
    ge25519_set_neutral(&r);
    ge25519_full_to_pniels(&w->table[k][0], &r);
    ge25519_full_to_pniels(&w->table[k][1], m->P[k]);
    ge25519_double(&d1, m->P[k]);
    ge25519_full_to_pniels(&w->table[k][2], &d1);
    for (int i = 1; i < 7; i++)
      ge25519_pnielsadd(&w->table[k][i + 2], &d1, &w->table[k][i]);
  }
  ge25519_set_neutral(&r);
  for (int i = 63; i >= 0; i--) {
    ge25519_double_partial(&r, &r);
    ge25519_double_partial(&r, &r);
    ge25519_double_partial(&r, &r);
    ge25519_double_p1p1(&t, &r);
    for (int k = 0; k < m->cnt; k++) {
      int v = w->digits[k][i];
      int sgn = (int)((unsigned char)v >> 7);
      int a = (v ^ -sgn) + sgn; /* |v| without a branch */
      ge25519_move_conditional_pniels_array(&pre, w->table[k], a, 9);
      ge25519_p1p1_to_full(&r, &t);
      ge25519_pnielsadd_p1p1(&t, &r, &pre, (unsigned char)sgn);
    }
    ge25519_p1p1_to_partial(&r, &t);
  }
  curve25519_mul(r.t, t.x, t.y);
  ge25519_add(acc, acc, &r, 0);
  memzero(w->digits, sizeof(w->digits));
  memzero(m->s, sizeof(m->s));
  memzero(&pre, sizeof(pre));
  memzero(&r, sizeof(r));
  memzero(&t, sizeof(t));
  m->cnt = 0;
}

static void msm_add(xmr_msm_ct_tables *w, ge25519 *acc, msm_pending *m,
                    const bignum256modm s, const ge25519 *P) {
  copy256_modm(m->s[m->cnt], s);
  m->P[m->cnt] = P;
  if (++m->cnt == (int)XMR_MSM_CT_POINTS) msm_flush(w, acc, m);
}

static uint32_t amount_bit(const bpp_ctx *c, size_t idx) {
  size_t j = idx / XMR_BPP_N;
  return j < c->m ? (uint32_t)((c->amounts[j] >> (idx % XMR_BPP_N)) & 1u) : 0u;
}

/* aL1[idx] = aL - z ; aR1[idx] = aL - 1 + z + d[idx] * y^(MN-idx) */
static void stream_ab(const bpp_ctx *c, size_t idx, bignum256modm a,
                      bignum256modm b) {
  bignum256modm bit, t, one, yb;
  copy256_modm(yb, c->ypw[c->logMN]);
  for (size_t k = 0; k < c->logMN; k++)
    if ((idx >> k) & 1) mul256_modm(yb, yb, c->yinvpw[k]); /* public index */
  set256_modm(bit, amount_bit(c, idx));
  set256_modm(one, 1);
  sub256_modm(a, bit, c->z);
  sub256_modm(b, bit, one);
  add256_modm(b, b, c->z);
  set256_modm(t, (uint64_t)1 << (idx % XMR_BPP_N));
  mul256_modm(t, t, c->z2pow[idx / XMR_BPP_N]);
  mul256_modm(t, t, yb);
  add256_modm(b, b, t);
  memzero(bit, sizeof(bit));
}

/* a'/b' entry idx at fold level `level`, recomputed from the stream. Leaf
 * idx + sum_t b_t*(MN>>(t+1)); coefficient prod_t (b_t ? ka_t : e_t) for a,
 * (b_t ? e_t : einv_t) for b. */
static void eval_ab(const bpp_ctx *c, int level, size_t idx, bignum256modm a,
                    bignum256modm b) {
  bignum256modm ca, cb, la, lb;
  set256_modm(a, 0);
  set256_modm(b, 0);
  for (size_t bits = 0; bits < ((size_t)1 << level); bits++) {
    size_t leaf = idx;
    set256_modm(ca, 1);
    set256_modm(cb, 1);
    for (int t = 0; t < level; t++) {
      if ((bits >> t) & 1) {
        leaf += c->MN >> (t + 1);
        mul256_modm(ca, ca, c->ch_ka[t]);
        mul256_modm(cb, cb, c->ch_e[t]);
      } else {
        mul256_modm(ca, ca, c->ch_e[t]);
        mul256_modm(cb, cb, c->ch_einv[t]);
      }
    }
    stream_ab(c, leaf, la, lb);
    mul256_modm(la, la, ca);
    add256_modm(a, a, la);
    mul256_modm(lb, lb, cb);
    add256_modm(b, b, lb);
  }
  memzero(la, sizeof(la));
  memzero(lb, sizeof(lb));
}

/* Round entries i and np+i: G_lo, G_hi, H_lo, H_hi (public points). */
static void fetch(const bpp_ctx *c, int round, size_t i, size_t np, ge25519 *Gl,
                  ge25519 *Gh, ge25519 *Hl, ge25519 *Hh) {
  if (round == 0) {
    generator(Gl, 0, i);
    generator(Gh, 0, np + i);
    generator(Hl, 1, i);
    generator(Hh, 1, np + i);
  } else {
    ge25519_unpack_vartime(Gl, c->ws->g_fold[i]);
    ge25519_unpack_vartime(Gh, c->ws->g_fold[np + i]);
    ge25519_unpack_vartime(Hl, c->ws->h_fold[i]);
    ge25519_unpack_vartime(Hh, c->ws->h_fold[np + i]);
  }
}

/* out = c*inv8*H + d*inv8*G + acc */
static void finish_LR(uint8_t out[32], const bpp_ctx *c, ge25519 *acc,
                      const bignum256modm cc, const bignum256modm d) {
  bignum256modm t;
  ge25519 P;
  mul256_modm(t, cc, c->inv8);
  ge25519_scalarmult(&P, &xmr_h, t);
  ge25519_add(acc, acc, &P, 0);
  mul256_modm(t, d, c->inv8);
  ge_base(&P, t);
  ge25519_add(acc, acc, &P, 0);
  ge25519_pack(out, acc);
  memzero(t, sizeof(t));
  memzero(&P, sizeof(P));
}

/* transcript = H(transcript || (H(V[0] || ...) mod l)) */
static void transcript_V(uint8_t T[32], const xmr_bpp_proof *out, size_t m) {
  SHA3_CTX k;
  uint8_t h[32];
  bignum256modm t;
  keccak_256_Init(&k);
  for (size_t j = 0; j < m; j++) keccak_Update(&k, out->V[j], 32);
  keccak_Final(&k, h);
  expand256_modm(t, h, 32);
  contract256_modm(h, t);
  transcript_update(T, h, NULL);
}

/* A = inv8 * (sum_i bit_i ? Gi : -Hi) + inv8*alpha*G (constant-time select).
 * The workspace is not used here. */
static bpp_rc __attribute__((noinline)) bpp_commit_A(
    bpp_ctx *c, uint8_t A[32], const bignum256modm alpha) {
  ge25519 P, Q, acc;
  bignum256modm t;
  bpp_rc rc = BPP_OK;
  ge25519_set_neutral(&acc);
  for (size_t i = 0; i < c->MN; i++) {
    generator(&P, 0, i);
    generator(&Q, 1, i);
    ge25519_neg_full(&Q);
    ge_cmov(&Q, &P, amount_bit(c, i));
    ge25519_add(&acc, &acc, &Q, 0);
    if (!step(c)) {
      rc = BPP_ABORTED;
      goto out;
    }
  }
  ge25519_scalarmult(&P, &acc, c->inv8);
  mul256_modm(t, alpha, c->inv8);
  ge_base(&Q, t);
  ge25519_add(&P, &P, &Q, 0);
  ge25519_pack(A, &P);
out:
  memzero(&acc, sizeof(acc));
  memzero(&P, sizeof(P));
  memzero(&Q, sizeof(Q));
  memzero(t, sizeof(t));
  return rc;
}

/* One round's L and R (before its challenge). */
static bpp_rc __attribute__((noinline)) bpp_lr(bpp_ctx *c, int round, size_t np,
                                               int lg, uint8_t L[32],
                                               uint8_t R[32],
                                               const bignum256modm dL,
                                               const bignum256modm dR) {
  const bignum256modm *ynp = &c->ypw[lg], *yinvnp = &c->yinvpw[lg];
  bignum256modm cL, cR, yfw, al, ah, bl, bh, t;
  ge25519 Gl, Gh, Hl, Hh, Lacc, Racc;
  msm_pending pend, pendR;
  bpp_rc rc = BPP_OK;
  pend.cnt = 0;
  pendR.cnt = 0;
  set256_modm(cL, 0);
  set256_modm(cR, 0);
  copy256_modm(yfw, c->y);
  ge25519_set_neutral(&Lacc);
  ge25519_set_neutral(&Racc);
  for (size_t i = 0; i < np; i++) {
    fetch(c, round, i, np, &Gl, &Gh, &Hl, &Hh);
    eval_ab(c, round, i, al, bl);
    eval_ab(c, round, np + i, ah, bh);
    /* cL += al*bh*y^(i+1); cR += ah*y^np*bl*y^(i+1) */
    mul256_modm(t, al, bh);
    mul256_modm(t, t, yfw);
    add256_modm(cL, cL, t);
    mul256_modm(t, ah, *ynp);
    mul256_modm(t, t, bl);
    mul256_modm(t, t, yfw);
    add256_modm(cR, cR, t);
    mul256_modm(yfw, yfw, c->y);
    /* L: al*yinv^np/8 * Gh + bh/8 * Hl ; R: ah*y^np/8 * Gl + bl/8 * Hh.
     * Each pair fills and flushes one batch, so nothing stays pending. */
    mul256_modm(t, al, *yinvnp);
    mul256_modm(t, t, c->inv8);
    msm_add(&c->ws->msm, &Lacc, &pend, t, &Gh);
    mul256_modm(t, bh, c->inv8);
    msm_add(&c->ws->msm, &Lacc, &pend, t, &Hl);
    mul256_modm(t, ah, *ynp);
    mul256_modm(t, t, c->inv8);
    msm_add(&c->ws->msm, &Racc, &pendR, t, &Gl);
    mul256_modm(t, bl, c->inv8);
    msm_add(&c->ws->msm, &Racc, &pendR, t, &Hh);
    if (!step(c)) {
      rc = BPP_ABORTED;
      goto out;
    }
  }
  finish_LR(L, c, &Lacc, cL, dL);
  finish_LR(R, c, &Racc, cR, dR);
out:
  memzero(al, sizeof(al));
  memzero(ah, sizeof(ah));
  memzero(bl, sizeof(bl));
  memzero(bh, sizeof(bh));
  memzero(cL, sizeof(cL));
  memzero(cR, sizeof(cR));
  memzero(t, sizeof(t));
  memzero(&pend, sizeof(pend));
  memzero(&pendR, sizeof(pendR));
  memzero(&Lacc, sizeof(Lacc));
  memzero(&Racc, sizeof(Racc));
  return rc;
}

/* Fold in place: G' = einv*Gl + yinv^np*e*Gh ; H' = e*Hl + einv*Hh. Public
 * challenges and public generators only. */
static bpp_rc __attribute__((noinline)) bpp_fold(bpp_ctx *c, int round,
                                                 size_t np, int lg,
                                                 const bignum256modm e,
                                                 const bignum256modm einv) {
  bignum256modm gk;
  ge25519 Gl, Gh, Hl, Hh, P;
  mul256_modm(gk, c->yinvpw[lg], e);
  for (size_t i = 0; i < np; i++) {
    fetch(c, round, i, np, &Gl, &Gh, &Hl, &Hh);
    ge25519_double_scalarmult_vartime2(&P, &Gl, einv, &Gh, gk);
    ge25519_pack(c->ws->g_fold[i], &P);
    ge25519_double_scalarmult_vartime2(&P, &Hl, e, &Hh, einv);
    ge25519_pack(c->ws->h_fold[i], &P);
    if (!step(c)) return BPP_ABORTED;
  }
  return BPP_OK;
}

/* Final round: A1, B, r1, s1, d1. */
static bpp_rc __attribute__((noinline)) bpp_final(bpp_ctx *c,
                                                  xmr_bpp_proof *out,
                                                  uint8_t T[32],
                                                  const bignum256modm alpha1) {
  bignum256modm r, s, d_, eta, a0, b0, t, t2, e;
  ge25519 P, P1, acc; /* P, P1 distinct: pending slots hold pointers */
  msm_pending pend;
  bpp_rc rc = BPP_OK;
  pend.cnt = 0;
  xmr_sc_nonce(r, c->nk, 'r', 0, T);
  xmr_sc_nonce(s, c->nk, 's', 0, T);
  xmr_sc_nonce(d_, c->nk, 'd', 0, T);
  xmr_sc_nonce(eta, c->nk, 'e', 0, T);
  eval_ab(c, (int)c->logMN, 0, a0, b0);
  ge25519_set_neutral(&acc);
  ge25519_unpack_vartime(&P, c->ws->g_fold[0]);
  ge25519_unpack_vartime(&P1, c->ws->h_fold[0]);
  mul256_modm(t, r, c->inv8);
  msm_add(&c->ws->msm, &acc, &pend, t, &P);
  mul256_modm(t, s, c->inv8);
  msm_add(&c->ws->msm, &acc, &pend, t, &P1);
  /* (r*y*b0 + s*y*a0)/8 * H */
  mul256_modm(t, r, c->y);
  mul256_modm(t, t, b0);
  mul256_modm(t2, s, c->y);
  mul256_modm(t2, t2, a0);
  add256_modm(t, t, t2);
  mul256_modm(t, t, c->inv8);
  msm_add(&c->ws->msm, &acc, &pend, t, &xmr_h);
  msm_flush(&c->ws->msm, &acc, &pend);
  mul256_modm(t, d_, c->inv8);
  ge_base(&P, t);
  ge25519_add(&acc, &acc, &P, 0);
  ge25519_pack(out->A1, &acc);
  /* B = eta/8 G + r*y*s/8 H */
  mul256_modm(t, r, c->y);
  mul256_modm(t, t, s);
  mul256_modm(t, t, c->inv8);
  mul256_modm(t2, eta, c->inv8);
  xmr_add_keys2(&P, t2, t, &xmr_h);
  ge25519_pack(out->B, &P);

  transcript_update(T, out->A1, out->B);
  expand256_modm(e, T, 32);
  if (iszero256_modm(e)) rc = BPP_FAIL;
  /* r1 = r + a0 e ; s1 = s + b0 e ; d1 = eta + d_ e + alpha1 e^2 */
  mul256_modm(t, a0, e);
  add256_modm(t, t, r);
  contract256_modm(out->r1, t);
  mul256_modm(t, b0, e);
  add256_modm(t, t, s);
  contract256_modm(out->s1, t);
  mul256_modm(t, d_, e);
  add256_modm(t, t, eta);
  mul256_modm(t2, e, e);
  mul256_modm(t2, t2, alpha1);
  add256_modm(t, t, t2);
  contract256_modm(out->d1, t);
  memzero(r, sizeof(r));
  memzero(s, sizeof(s));
  memzero(d_, sizeof(d_));
  memzero(eta, sizeof(eta));
  memzero(a0, sizeof(a0));
  memzero(b0, sizeof(b0));
  memzero(t, sizeof(t));
  memzero(t2, sizeof(t2));
  memzero(&pend, sizeof(pend));
  memzero(&acc, sizeof(acc));
  memzero(&P, sizeof(P));
  return rc;
}

/* Hedge key: secret = gamma[0..m) || le64 amount[0..m), transcript = T after
 * V. Every BP+ nonce is xmr_sc_nonce(nk, tag, round, current T). */
static bool bpp_hedge(bpp_ctx *c, const uint8_t (*gamma)[32],
                      const uint8_t T[32]) {
  uint8_t secret[XMR_BPP_MAX_OUTPUTS * 40];
  size_t n = 0;
  for (size_t j = 0; j < c->m; j++) {
    memcpy(secret + n, gamma[j], 32);
    n += 32;
    for (int b = 0; b < 8; b++)
      secret[n++] = (uint8_t)(c->amounts[j] >> (8 * b));
  }
  bool ok = xmr_hedge_key(c->nk, BPP_HEDGE_DOMAIN, secret, n, T, 32);
  memzero(secret, sizeof(secret));
  return ok;
}

bool xmr_bpp_prove(xmr_bpp_proof *out, const uint64_t *amounts,
                   const uint8_t (*gamma)[32], size_t m, xmr_bpp_workspace *ws,
                   xmr_progress_fn progress, void *progress_ctx) {
  bpp_ctx c;
  bignum256modm t, t2, g, alpha, alpha1, e, einv, dL, dR;
  uint8_t T[32];
  bpp_rc rc = BPP_FAIL;
  bool ws_dirty = false;

  if (out == NULL) return false;
  memzero(out, sizeof(*out));
  memzero(&c, sizeof(c));
  if (amounts == NULL || gamma == NULL || ws == NULL || m == 0 ||
      m > XMR_BPP_MAX_OUTPUTS || ((uintptr_t)ws % XMR_WORKSPACE_ALIGN) != 0) {
    return false;
  }
  for (size_t j = 0; j < m; j++) {
    if (!xmr_sc_load_canonical(g, gamma[j])) {
      memzero(g, sizeof(g));
      return false;
    }
  }
  c.m = m;
  c.amounts = amounts;
  c.M = m == 1 ? 1 : 2;
  c.MN = c.M * XMR_BPP_N;
  c.logMN = c.M == 1 ? 6 : 7;
  c.ws = ws;
  c.progress = progress;
  c.progress_ctx = progress_ctx;
  c.total = (uint32_t)(c.MN + 2 * (c.MN - 1));
  expand256_modm(c.inv8, xmr_inv_eight, 32);

  /* V[j] = gamma/8 G + v/8 H */
  out->n_outputs = (uint8_t)m;
  out->n_rounds = (uint8_t)c.logMN;
  for (size_t j = 0; j < m; j++) {
    ge25519 P;
    xmr_sc_load_canonical(g, gamma[j]);
    mul256_modm(g, g, c.inv8);
    set256_modm(t, amounts[j]);
    mul256_modm(t, t, c.inv8);
    xmr_add_keys2(&P, g, t, &xmr_h);
    ge25519_pack(out->V[j], &P);
    memzero(&P, sizeof(P));
  }
  memzero(g, sizeof(g));

  memcpy(T, INITIAL_TRANSCRIPT, 32);
  transcript_V(T, out, m);
  if (!bpp_hedge(&c, gamma, T)) goto done;

  xmr_sc_nonce(alpha, c.nk, 'a', 0, T);
  rc = bpp_commit_A(&c, out->A, alpha);
  if (rc != BPP_OK) goto done;

  /* y, z */
  transcript_update(T, out->A, NULL);
  expand256_modm(c.y, T, 32);
  xmr_hash_to_scalar(c.z, T, 32);
  contract256_modm(T, c.z);
  if (iszero256_modm(c.y) || iszero256_modm(c.z)) {
    rc = BPP_FAIL;
    goto done;
  }
  mul256_modm(c.z2pow[0], c.z, c.z);
  for (size_t j = 1; j < c.M; j++)
    mul256_modm(c.z2pow[j], c.z2pow[j - 1], c.z2pow[0]);
  xmr_sc_invert(c.yinv, c.y);
  copy256_modm(c.ypw[0], c.y);
  copy256_modm(c.yinvpw[0], c.yinv);
  for (size_t k = 1; k <= c.logMN; k++) {
    mul256_modm(c.ypw[k], c.ypw[k - 1], c.ypw[k - 1]);
    mul256_modm(c.yinvpw[k], c.yinvpw[k - 1], c.yinvpw[k - 1]);
  }

  /* alpha1 = alpha + sum_j y^(MN+1) z^(2(j+1)) gamma_j */
  copy256_modm(alpha1, alpha);
  mul256_modm(t2, c.ypw[c.logMN], c.y); /* y^(MN+1) */
  for (size_t j = 0; j < m; j++) {
    xmr_sc_load_canonical(g, gamma[j]);
    mul256_modm(t, t2, c.z2pow[j]);
    mul256_modm(t, t, g);
    add256_modm(alpha1, alpha1, t);
  }
  memzero(g, sizeof(g));
  memzero(alpha, sizeof(alpha));

  /* inner-product rounds */
  ws_dirty = true;
  size_t n = c.MN;
  for (int round = 0; n > 1; round++) {
    size_t np = n / 2;
    int lg = (int)(c.logMN - 1 - (size_t)round); /* np = 2^lg */
    xmr_sc_nonce(dL, c.nk, 'L', (uint8_t)round, T);
    xmr_sc_nonce(dR, c.nk, 'R', (uint8_t)round, T);
    rc = bpp_lr(&c, round, np, lg, out->L[round], out->R[round], dL, dR);
    if (rc != BPP_OK) goto done;
    transcript_update(T, out->L[round], out->R[round]);
    expand256_modm(e, T, 32);
    if (iszero256_modm(e)) {
      rc = BPP_FAIL;
      goto done;
    }
    xmr_sc_invert(einv, e);
    copy256_modm(c.ch_e[round], e);
    copy256_modm(c.ch_einv[round], einv);
    mul256_modm(c.ch_ka[round], einv, c.ypw[lg]);
    rc = bpp_fold(&c, round, np, lg, e, einv);
    if (rc != BPP_OK) goto done;
    mul256_modm(t, e, e);
    mul256_modm(t, t, dL);
    add256_modm(alpha1, alpha1, t);
    mul256_modm(t, einv, einv);
    mul256_modm(t, t, dR);
    add256_modm(alpha1, alpha1, t);
    n = np;
  }
  rc = bpp_final(&c, out, T, alpha1);

done:
  memzero(alpha, sizeof(alpha));
  memzero(alpha1, sizeof(alpha1));
  memzero(dL, sizeof(dL));
  memzero(dR, sizeof(dR));
  memzero(t, sizeof(t));
  memzero(t2, sizeof(t2));
  /* An aborted call must not touch the workspace: the caller may already
   * have handed it to an inbound frame. It holds no secret at that point. */
  if (ws_dirty && rc != BPP_ABORTED) memzero(ws, sizeof(*ws));
  memzero(&c, sizeof(c));
  if (rc != BPP_OK) {
    memzero(out, sizeof(*out));
    return false;
  }
  return true;
}

bool xmr_bpp_serialize(const xmr_bpp_proof *proof, uint8_t *out, size_t out_len,
                       size_t *written) {
  const xmr_bpp_proof *p = proof;
  if (p == NULL || out == NULL || written == NULL) return false;
  *written = 0;
  if (p->n_outputs < 1 || p->n_outputs > XMR_BPP_MAX_OUTPUTS ||
      p->n_rounds != (p->n_outputs == 1 ? 6 : 7)) {
    return false;
  }
  size_t need = 6 * 32 + 2 * (1 + (size_t)p->n_rounds * 32);
  if (out_len < need) return false;
  uint8_t *o = out;
  memcpy(o, p->A, 32);
  memcpy(o + 32, p->A1, 32);
  memcpy(o + 64, p->B, 32);
  memcpy(o + 96, p->r1, 32);
  memcpy(o + 128, p->s1, 32);
  memcpy(o + 160, p->d1, 32);
  o += 192;
  *o++ = p->n_rounds; /* varint, < 128 */
  memcpy(o, p->L, (size_t)p->n_rounds * 32);
  o += (size_t)p->n_rounds * 32;
  *o++ = p->n_rounds;
  memcpy(o, p->R, (size_t)p->n_rounds * 32);
  *written = need;
  return true;
}
