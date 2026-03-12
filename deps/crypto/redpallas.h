/*
 * RedPallas signature scheme for Zcash Orchard SpendAuth.
 *
 * RedPallas is a Schnorr-like signature scheme on the Pallas curve,
 * used for spend authorization in Zcash's Orchard protocol.
 *
 * The SpendAuth variant uses a specific generator point G_spendauth
 * (distinct from the Pallas curve generator) for key derivation and
 * signing.
 *
 * Copyright (C) 2025 KeepKey
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#ifndef REDPALLAS_H
#define REDPALLAS_H

#include "bignum.h"
#include "ecdsa.h"  /* for curve_point */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Compute [k] * G_spendauth on the Pallas curve.
 *
 * G_spendauth is the SpendAuth generator defined in the Zcash protocol
 * spec (§5.4.9.7). This is NOT the standard Pallas generator.
 *
 * @param k    Scalar multiplier (bignum256, reduced mod q)
 * @param out  Resulting affine point (x, y)
 */
void redpallas_scalar_mult_spendauth_G(const bignum256 *k, curve_point *out);

/*
 * Produce a RedPallas SpendAuth signature.
 *
 * sig = (R, S) where:
 *   T   = BLAKE2b-512("Zcash_RedPallasH", sk || alpha || digest)
 *   r   = T mod q
 *   R   = [r] * G_spendauth
 *   rsk = sk + alpha  (mod q)          -- re-randomized signing key
 *   S   = r + e * rsk (mod q)          -- e = H*(R || vk || digest)
 *
 * The output signature is 64 bytes: R_bytes[32] || S_bytes[32].
 *
 * @param sk      32-byte spend authorizing key (ask), little-endian
 * @param alpha   32-byte randomizer, little-endian
 * @param digest  32-byte message digest (sighash)
 * @param sig_out 64-byte output signature
 * @return 0 on success, non-zero on error
 */
int redpallas_sign_digest(const uint8_t sk[32],
                          const uint8_t alpha[32],
                          const uint8_t digest[32],
                          uint8_t sig_out[64]);

#ifdef __cplusplus
}
#endif

#endif /* REDPALLAS_H */
