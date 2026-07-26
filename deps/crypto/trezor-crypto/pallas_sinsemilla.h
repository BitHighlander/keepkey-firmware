/**
 * Copyright (c) 2026 KeepKey
 *
 * Minimal Sinsemilla primitives needed for Zcash Orchard key derivation.
 */

#ifndef __PALLAS_SINSEMILLA_H__
#define __PALLAS_SINSEMILLA_H__

#include <stddef.h>
#include <stdint.h>

#include "ecdsa.h"

#define PALLAS_SINSEMILLA_K 10
#define PALLAS_SINSEMILLA_C 253
#define PALLAS_SINSEMILLA_MAX_BITS (PALLAS_SINSEMILLA_K * PALLAS_SINSEMILLA_C)

/*
 * Compute SinsemillaHashToPoint(Q, msg).
 *
 * msg is a packed little-endian bit string: bit i is read from
 * msg[i / 8] >> (i % 8). msg_bits must be <= PALLAS_SINSEMILLA_MAX_BITS.
 */
int pallas_sinsemilla_hash_to_point(const curve_point* q, const uint8_t* msg,
                                    size_t msg_bits, curve_point* out);

/*
 * Compute SinsemillaHash(Q, msg), returning the little-endian Pallas base-field
 * x-coordinate extracted from SinsemillaHashToPoint.
 */
int pallas_sinsemilla_hash(const curve_point* q, const uint8_t* msg,
                           size_t msg_bits, uint8_t hash_out[32]);

/*
 * Compute SinsemillaCommit(Q, R, msg, r).
 *
 * blind is a canonical Pallas scalar-field encoding and must be public
 * transaction data. Secret rivk commitments use the dedicated IVK API below.
 */
int pallas_sinsemilla_commit(const curve_point* q, const curve_point* r,
                             const uint8_t* msg, size_t msg_bits,
                             const uint8_t blind[32], curve_point* out);

/*
 * Compute SinsemillaShortCommit(Q, R, msg, r), returning the little-endian
 * Pallas base-field x-coordinate extracted from SinsemillaCommit.
 */
int pallas_sinsemilla_short_commit(const curve_point* q, const curve_point* r,
                                   const uint8_t* msg, size_t msg_bits,
                                   const uint8_t blind[32], uint8_t out[32]);

/*
 * Compute Commit^ivk.Output = SinsemillaShortCommit(
 *     "z.cash:Orchard-CommitIvk", I2LEBSP_255(ak) || I2LEBSP_255(nk), rivk)
 *
 * ak and nk are canonical Pallas base-field encodings. rivk is a canonical
 * Pallas scalar-field encoding. ivk_out receives the 32-byte LE Pallas
 * base-field output; callers must reject zero where required by Orchard IVKs.
 */
int pallas_sinsemilla_commit_ivk(const uint8_t ak[32], const uint8_t nk[32],
                                 const uint8_t rivk[32], uint8_t ivk_out[32]);

#endif
