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
 * Monero signing crypto: the Bulletproofs+ range prover (1 or 2 outputs) and
 * the CLSAG ring signer. Both produce the exact bytes Monero Core v0.18.5.4
 * verifies (bulletproof_plus_VERIFY, verRctCLSAGSimple); the unit tests embed
 * vectors that Core accepted when they were generated.
 *
 * RANDOMNESS. Every nonce is hedged: one 32-byte draw from
 * random_buffer_checked() is hashed with the secret witness and the public
 * transcript (xmr_hedge_key), and every nonce is derived from that key. A weak
 * but healthy-looking RNG therefore cannot repeat a nonce across different
 * messages (the CVE-2020-6861 class). A failed draw makes the call return
 * false with every output zeroed: no proof and no signature leaves this
 * module. xmr_random_scalar() (an unchecked random_buffer() draw in
 * trezor-crypto) is never called.
 *
 * MEMORY. The big buffers are supplied by the caller so that the signer can
 * time-share them from frame_arena (lib/board/messages.c). They are plain
 * structs so their size is a compile-time constant:
 *
 *   xmr_bpp_workspace    7,104 B   folded generators 4,096 + CT msm tables
 *   xmr_clsag_workspace  5,408 B   two Keccak states 800 + vartime tables
 *
 * Both fit the smallest frame arena (ARM, MAX_FRAME_SIZE = 12 KiB). Alignment
 * must be at least XMR_WORKSPACE_ALIGN; a misaligned pointer is refused.
 *
 * ABORT CONTRACT. The optional progress callback runs only at points where the
 * workspace holds no secret: the CT tables then hold multiples of public
 * generators and the window digits and scalars have been wiped. A stray USB
 * frame received inside the callback may therefore overwrite the workspace
 * freely. When the callback returns false the call wipes its own stack
 * secrets and the output, does NOT read or write the workspace again, and
 * returns false. On every other return the workspace is wiped before return.
 *
 * CONSTANT TIME. Every product with a secret scalar uses a fixed-window
 * constant-time ladder (ge25519_scalarmult, ge25519_scalarmult_base_niels, or
 * the fixed 4-bit window multiexp here). That covers the BP+ A, L, R, A1, B
 * and V commitments and the CLSAG key image, D, alpha*G, alpha*Hp(P) and s_l.
 * Variable time is used only on public data: BP+ generator folding (public
 * challenges times public generators) and the CLSAG decoy rounds. There is no
 * variable-time L/R option. Residual: the Cortex-M3 UMULL/UMLAL instructions
 * retire early on small operands. That is shared by every ed25519 operation
 * in the firmware and is not addressed here.
 *
 * CLSAG REAL INDEX. The decoy rounds run in variable time on public values,
 * starting at real_index + 1 and skipping real_index. Their timing is a
 * function of the published signature, so an observer who can time the whole
 * signature (or watch power/EM per round) can recompute the time of every
 * round and learn which one was not computed: the real index. That reveals
 * which ring member is spent (privacy), never a key. The host already knows
 * the real index because it supplies it. Constant-time decoy rounds would
 * cost about 2.5x the CLSAG time and are not done.
 *
 * STACK HYGIENE. Every secret buffer this module owns is wiped with memzero on
 * every exit path. The donna primitives it calls do not wipe their own
 * temporaries; their frames sit below this module's and are reused by the
 * next call.
 */

#ifndef KEEPKEY_FIRMWARE_MONERO_CRYPTO_H
#define KEEPKEY_FIRMWARE_MONERO_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "trezor/crypto/ed25519-donna/ed25519-donna.h"
#include "trezor/crypto/sha3.h"

/* ARM MAX_FRAME_SIZE (include/keepkey/transport/trezor_transport.h): the
 * frame arena is at least this big on every target. */
#define XMR_FRAME_ARENA_FLOOR_BYTES (12u * 1024u)
#define XMR_WORKSPACE_ALIGN 8u

/* ---------------------------------------------------------------- hedging */

/* out = Keccak256(pad32(domain) || le32(len) || secret || le32(len) ||
 *                 transcript || rng32), rng32 from random_buffer_checked().
 * domain is at most 32 bytes. Also the helper for any other transaction
 * secret (for example the per-transaction master key). Returns false, with
 * out zeroed, if the draw fails or an argument is invalid. */
bool xmr_hedge_key(uint8_t out[32], const char *domain, const uint8_t *secret,
                   size_t secret_len, const uint8_t *transcript,
                   size_t transcript_len);

/* The module's only randomness: random_buffer_checked(out, 32). Kept in its
 * own translation unit (crypto_rng.c) and nowhere else. */
bool xmr_crypto_rng32(uint8_t out[32]);

/* Progress and abort hook. Return false to abort. See ABORT CONTRACT. */
typedef bool (*xmr_progress_fn)(void *ctx, uint32_t done, uint32_t total);

/* ---------------------------------------------------------- Bulletproofs+ */

#define XMR_BPP_N 64u
#define XMR_BPP_MAX_OUTPUTS 2u
#define XMR_BPP_MAX_MN (XMR_BPP_N * XMR_BPP_MAX_OUTPUTS)
#define XMR_BPP_MAX_ROUNDS 7u
/* Points per constant-time Straus batch (doublings shared). */
#define XMR_MSM_CT_POINTS 2u

/* Core's binary layout of one proof, V omitted: A, A1, B, r1, s1, d1, then
 * L and R, each a varint count followed by the keys. 642 B for 2 outputs,
 * 578 B for 1. */
#define XMR_BPP_SERIALIZED_MAX (6u * 32u + 2u * (1u + XMR_BPP_MAX_ROUNDS * 32u))

typedef struct {
  uint8_t n_outputs;                  /* m, 1 or 2 */
  uint8_t n_rounds;                   /* log2(M * 64): 6 or 7 */
  uint8_t V[XMR_BPP_MAX_OUTPUTS][32]; /* gamma/8 * G + v/8 * H */
  uint8_t A[32], A1[32], B[32];
  uint8_t r1[32], s1[32], d1[32];
  uint8_t L[XMR_BPP_MAX_ROUNDS][32], R[XMR_BPP_MAX_ROUNDS][32];
} xmr_bpp_proof;

typedef struct {
  ge25519_pniels table[XMR_MSM_CT_POINTS][9];
  signed char digits[XMR_MSM_CT_POINTS][64];
} xmr_msm_ct_tables;

typedef struct {
  xmr_msm_ct_tables msm;
  uint8_t g_fold[XMR_BPP_MAX_MN / 2u][32];
  uint8_t h_fold[XMR_BPP_MAX_MN / 2u][32];
} xmr_bpp_workspace;

#define XMR_BPP_WORKSPACE_BYTES 7104u

/* Prove that amounts[j] is in [0, 2^64) for m = 1 or 2 outputs with masks
 * gamma[j] (canonical 32-byte little-endian scalars). On success out holds
 * the proof and its V. 2 outputs: 0.96 G Cortex-M3 instructions (measured in
 * Unicorn), 13-21 s at 120 MHz.
 * Returns false, with *out zeroed, on any failure. */
bool xmr_bpp_prove(xmr_bpp_proof *out, const uint64_t *amounts,
                   const uint8_t (*gamma)[32], size_t m, xmr_bpp_workspace *ws,
                   xmr_progress_fn progress, void *progress_ctx);

/* Writes Core's layout (see XMR_BPP_SERIALIZED_MAX). Returns false if out_len
 * is too small or the proof is malformed. */
bool xmr_bpp_serialize(const xmr_bpp_proof *proof, uint8_t *out, size_t out_len,
                       size_t *written);

/* ------------------------------------------------------------------ CLSAG */

#define XMR_CLSAG_MAX_RING 16u

typedef struct {
  uint8_t s[XMR_CLSAG_MAX_RING][32];
  uint8_t c1[32];
  uint8_t D[32]; /* D/8, as serialized */
  uint8_t I[32]; /* key image p * Hp(P[l]); not serialized */
} xmr_clsag_sig;

typedef struct {
  SHA3_CTX prefix; /* round-hash prefix: domain, P, C, C_offset, message */
  SHA3_CTX round;
  ge25519_pniels pre[3][8];
  signed char slide[3][256];
} xmr_clsag_workspace;

#define XMR_CLSAG_WORKSPACE_BYTES 5408u

/* CLSAG over ring (P[i], C_nonzero[i]), i < n, 2 <= n <= 16, pseudo-output
 * C_offset, real member l, spend secret p (P[l] = p*G) and commitment secret
 * z (C_nonzero[l] - C_offset = z*G). Both relations are checked first; any
 * mismatch or undecodable point returns false. Returns false, with *sig
 * zeroed, on any failure. */
bool xmr_clsag_sign(xmr_clsag_sig *sig, const uint8_t message[32],
                    const uint8_t (*P)[32], const uint8_t (*C_nonzero)[32],
                    const uint8_t C_offset[32], size_t n, size_t real_index,
                    const uint8_t p[32], const uint8_t z[32],
                    xmr_clsag_workspace *ws, xmr_progress_fn progress,
                    void *progress_ctx);

#endif
