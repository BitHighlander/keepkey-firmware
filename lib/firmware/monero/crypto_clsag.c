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
 * CLSAG signer: Monero Core v0.18.5.4 CLSAG_Gen with device_default
 * clsag_prepare / clsag_sign (src/ringct/rctSigs.cpp,
 * src/device/device_default.cpp). Products with p, z or alpha are constant
 * time (I = pH, D = zH, alpha*G, alpha*H, s_l). The decoy rounds use only
 * public values and a variable-time 3-point Straus multiexp; see CLSAG REAL
 * INDEX in crypto.h for what that timing reveals.
 */

#include <string.h>

#include "crypto_internal.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/monero/xmr.h"

_Static_assert(sizeof(xmr_clsag_workspace) == XMR_CLSAG_WORKSPACE_BYTES,
               "update XMR_CLSAG_WORKSPACE_BYTES and the signer's arena plan");
_Static_assert(XMR_CLSAG_WORKSPACE_BYTES <= XMR_FRAME_ARENA_FLOOR_BYTES,
               "the CLSAG workspace must fit the ARM frame arena");

#define CLSAG_HEDGE_DOMAIN "KKXMR-clsag-v1"
#define VT_W 5
#define VT_TAB (1 << (VT_W - 2))

static void dom(SHA3_CTX *k, const char *d) {
  uint8_t b[32] = {0};
  memcpy(b, d, strlen(d));
  keccak_Update(k, b, 32);
}

static void hash_final_scalar(SHA3_CTX *k, bignum256modm r) {
  uint8_t h[32];
  keccak_Final(k, h);
  expand256_modm(r, h, 32);
}

/* r = sum s_k P_k, k < 3, variable time (public inputs only). */
static void __attribute__((noinline)) msm3_vartime(xmr_clsag_workspace *w,
                                                   ge25519 *r,
                                                   const ge25519 *P[3],
                                                   const bignum256modm *s[3]) {
  ge25519 d;
  ge25519_p1p1 t;
  for (int k = 0; k < 3; k++) {
    contract256_slidingwindow_modm(w->slide[k], *s[k], VT_W);
    ge25519_double(&d, P[k]);
    ge25519_full_to_pniels(&w->pre[k][0], P[k]);
    for (int i = 0; i < VT_TAB - 1; i++)
      ge25519_pnielsadd(&w->pre[k][i + 1], &d, &w->pre[k][i]);
  }
  ge25519_set_neutral(r);
  int i = 255;
  while (i >= 0 && !(w->slide[0][i] | w->slide[1][i] | w->slide[2][i])) i--;
  if (i < 0) return;
  for (; i >= 0; i--) {
    ge25519_double_p1p1(&t, r);
    for (int k = 0; k < 3; k++) {
      signed char v = w->slide[k][i];
      if (v) {
        ge25519_p1p1_to_full(r, &t);
        ge25519_pnielsadd_p1p1(&t, r, &w->pre[k][(v < 0 ? -v : v) / 2],
                               (unsigned char)v >> 7);
      }
    }
    ge25519_p1p1_to_partial(r, &t);
  }
  curve25519_mul(r->t, t.x, t.y);
}

static void scalarmult_packed(uint8_t out[32], const ge25519 *P,
                              const bignum256modm s) {
  ge25519 X;
  ge25519_scalarmult(&X, P, s);
  ge25519_pack(out, &X);
  memzero(&X, sizeof(X));
}

static void base_packed(uint8_t out[32], const bignum256modm s) {
  ge25519 X;
  ge25519_scalarmult_base_niels(&X, ge25519_niels_base_multiples, s);
  ge25519_pack(out, &X);
  memzero(&X, sizeof(X));
}

/* Ownership: P[l] == p*G and C_nonzero[l] - C_offset == z*G. */
static bool check_real_member(const uint8_t Pl[32], const uint8_t Cl[32],
                              const ge25519 *Coff, const bignum256modm p,
                              const bignum256modm z) {
  ge25519 C;
  uint8_t b[32];
  bool ok;
  base_packed(b, p);
  ok = xmr_eq32(b, Pl);
  if (ok) ok = ge25519_unpack_vartime(&C, Cl) != 0;
  if (ok) {
    ge25519_add(&C, &C, Coff, 1);
    ge25519_pack(b, &C);
    uint8_t zg[32];
    base_packed(zg, z);
    ok = xmr_eq32(b, zg);
    memzero(zg, sizeof(zg));
  }
  memzero(b, sizeof(b));
  return ok;
}

bool xmr_clsag_sign(xmr_clsag_sig *sig, const uint8_t message[32],
                    const uint8_t (*P)[32], const uint8_t (*C_nonzero)[32],
                    const uint8_t C_offset[32], size_t n, size_t real_index,
                    const uint8_t p[32], const uint8_t z[32],
                    xmr_clsag_workspace *ws, xmr_progress_fn progress,
                    void *progress_ctx) {
  static const uint8_t identity[32] = {1};
  const size_t l = real_index;
  bignum256modm ps, zs, a, mu[2], c, cp, cc, si, t;
  ge25519 Hl, I, D, Coff, Pi, Ci, Hi, X, G;
  uint8_t Lb[32], Rb[32], alpha_G[32], nk[32], tr[33], secret[64];
  bool ok = false, aborted = false;

  if (sig != NULL) memzero(sig, sizeof(*sig));
  if (ws == NULL || ((uintptr_t)ws % XMR_WORKSPACE_ALIGN) != 0) return false;
  if (sig == NULL || message == NULL || P == NULL || C_nonzero == NULL ||
      C_offset == NULL || p == NULL || z == NULL || n < 2 ||
      n > XMR_CLSAG_MAX_RING || l >= n) {
    memzero(ws, sizeof(*ws));
    return false;
  }
  if (!xmr_sc_load_canonical(ps, p) || !xmr_sc_load_canonical(zs, z) ||
      iszero256_modm(ps) || iszero256_modm(zs) ||
      !xmr_point_load_canonical(&Coff, C_offset)) {
    goto done;
  }
  /* Validate every supplied encoding before hedging, including decoys. */
  for (size_t i = 0; i < n; i++) {
    if (!xmr_point_load_canonical(&Pi, P[i]) ||
        !xmr_point_load_canonical(&Ci, C_nonzero[i])) {
      goto done;
    }
  }
  if (!check_real_member(P[l], C_nonzero[l], &Coff, ps, zs)) goto done;
  ge25519_set_base(&G);

  /* round-hash prefix: domain, P, C_nonzero, C_offset, message */
  keccak_256_Init(&ws->prefix);
  dom(&ws->prefix, "CLSAG_round");
  for (size_t i = 0; i < n; i++) keccak_Update(&ws->prefix, P[i], 32);
  for (size_t i = 0; i < n; i++) keccak_Update(&ws->prefix, C_nonzero[i], 32);
  keccak_Update(&ws->prefix, C_offset, 32);
  keccak_Update(&ws->prefix, message, 32);

  /* Hedge key: secret p || z; transcript = H(round prefix) || l. Alpha and
   * the decoy s_i all derive from it. */
  memcpy(&ws->round, &ws->prefix, sizeof(SHA3_CTX));
  keccak_Final(&ws->round, tr);
  tr[32] = (uint8_t)l;
  memcpy(secret, p, 32);
  memcpy(secret + 32, z, 32);
  if (!xmr_hedge_key(nk, CLSAG_HEDGE_DOMAIN, secret, sizeof(secret), tr,
                     sizeof(tr))) {
    goto done;
  }
  xmr_sc_nonce(a, nk, 'a', 0, NULL);

  /* H = Hp(P[l]); I = pH; D = zH; aG; aH (all constant time) */
  xmr_hash_to_ec(&Hl, P[l], 32);
  ge25519_scalarmult(&I, &Hl, ps);
  ge25519_scalarmult(&D, &Hl, zs);
  ge25519_pack(sig->I, &I);
  expand256_modm(t, xmr_inv_eight, 32);
  scalarmult_packed(sig->D, &D, t);
  if (xmr_eq32(sig->I, identity) || xmr_eq32(sig->D, identity)) goto done;
  base_packed(alpha_G, a);
  scalarmult_packed(Rb, &Hl, a);

  /* mu_P, mu_C = H(dom, P, C_nonzero, I, D/8, C_offset) */
  for (int w = 0; w < 2; w++) {
    keccak_256_Init(&ws->round);
    dom(&ws->round, w ? "CLSAG_agg_1" : "CLSAG_agg_0");
    for (size_t i = 0; i < n; i++) keccak_Update(&ws->round, P[i], 32);
    for (size_t i = 0; i < n; i++) keccak_Update(&ws->round, C_nonzero[i], 32);
    keccak_Update(&ws->round, sig->I, 32);
    keccak_Update(&ws->round, sig->D, 32);
    keccak_Update(&ws->round, C_offset, 32);
    hash_final_scalar(&ws->round, mu[w]);
  }

  memcpy(&ws->round, &ws->prefix, sizeof(SHA3_CTX));
  keccak_Update(&ws->round, alpha_G, 32);
  keccak_Update(&ws->round, Rb, 32);
  hash_final_scalar(&ws->round, c);

  size_t i = (l + 1) % n;
  if (i == 0) contract256_modm(sig->c1, c);
  while (i != l) {
    xmr_sc_nonce(si, nk, 's', (uint8_t)i, NULL);
    contract256_modm(sig->s[i], si);
    mul256_modm(cp, mu[0], c);
    mul256_modm(cc, mu[1], c);
    if (!ge25519_unpack_vartime(&Pi, P[i]) ||
        !ge25519_unpack_vartime(&Ci, C_nonzero[i])) {
      goto done;
    }
    ge25519_add(&Ci, &Ci, &Coff, 1); /* C[i] = C_nonzero[i] - C_offset */
    xmr_hash_to_ec(&Hi, P[i], 32);
    {
      const ge25519 *pts[3] = {&G, &Pi, &Ci};
      const bignum256modm *sc[3] = {&si, &cp, &cc};
      msm3_vartime(ws, &X, pts, sc);
      ge25519_pack(Lb, &X);
    }
    {
      const ge25519 *pts[3] = {&Hi, &I, &D};
      const bignum256modm *sc[3] = {&si, &cp, &cc};
      msm3_vartime(ws, &X, pts, sc);
      ge25519_pack(Rb, &X);
    }
    memcpy(&ws->round, &ws->prefix, sizeof(SHA3_CTX));
    keccak_Update(&ws->round, Lb, 32);
    keccak_Update(&ws->round, Rb, 32);
    hash_final_scalar(&ws->round, c);
    i = (i + 1) % n;
    if (i == 0) contract256_modm(sig->c1, c);
    if (progress && !progress(progress_ctx, (uint32_t)((i + n - l - 1) % n),
                              (uint32_t)(n - 1))) {
      aborted = true;
      goto done;
    }
  }

  /* s_l = a - c * (mu_P p + mu_C z) */
  mul256_modm(t, mu[0], ps);
  mul256_modm(cc, mu[1], zs);
  add256_modm(t, t, cc);
  mul256_modm(t, t, c);
  sub256_modm(t, a, t);
  contract256_modm(sig->s[l], t);
  /* Check the serialized response against the original nonce commitment
   * before releasing it. Only the challenge and ring points enter the
   * variable-time product. A response that fails this check is secret. */
  if (!xmr_sc_load_canonical(t, sig->s[l]) ||
      !ge25519_unpack_vartime(&Pi, P[l]) ||
      !ge25519_unpack_vartime(&Ci, C_nonzero[l])) {
    goto done;
  }
  ge25519_add(&Ci, &Ci, &Coff, 1);
  mul256_modm(cp, c, mu[0]);
  mul256_modm(cc, c, mu[1]);
  ge25519_double_scalarmult_vartime2(&Hi, &Pi, cp, &Ci, cc);
  ge25519_scalarmult_base_niels(&X, ge25519_niels_base_multiples, t);
  ge25519_add(&X, &X, &Hi, 0);
  ge25519_pack(Lb, &X);
  ok = xmr_eq32(Lb, alpha_G);

done:
  memzero(alpha_G, sizeof(alpha_G));
  memzero(ps, sizeof(ps));
  memzero(zs, sizeof(zs));
  memzero(a, sizeof(a));
  memzero(t, sizeof(t));
  memzero(cc, sizeof(cc));
  memzero(nk, sizeof(nk));
  memzero(secret, sizeof(secret));
  memzero(Lb, sizeof(Lb));
  memzero(Rb, sizeof(Rb));
  memzero(&X, sizeof(X));
  memzero(&D, sizeof(D));
  /* An aborted call must not touch the workspace (see crypto.h). */
  if (!aborted) memzero(ws, sizeof(*ws));
  if (!ok) memzero(sig, sizeof(*sig));
  return ok;
}
