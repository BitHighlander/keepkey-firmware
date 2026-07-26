/**
 * Copyright (c) 2025 KeepKey
 *
 * RedPallas (re-randomized Schnorr) signature scheme for Zcash Orchard.
 * Used for spend authorization signatures in the Orchard shielded protocol.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __REDPALLAS_H__
#define __REDPALLAS_H__

#include <stdint.h>
#include "bignum.h"
#include "ecdsa.h"

typedef void (*redpallas_progress_callback)(uint32_t completed, uint32_t total,
                                            void* context);

/**
 * RedPallas spend authorization signature.
 *
 * Computes a re-randomized Schnorr signature over the Pallas curve:
 *   rsk = ask + alpha (mod order)        -- randomized signing key
 *   rk  = [rsk]G                         -- randomized verification key
 *   r   = random_scalar()                -- nonce
 *   R   = [r]G                           -- nonce commitment
 *   c   = H("Zcash_RedPallasH", R || rk || sighash)  -- challenge (mod order)
 *   S   = r + c * rsk (mod order)        -- response
 *   sig = R || S  (64 bytes)
 *
 * @param ask      32-byte spend authorizing key (little-endian scalar)
 * @param alpha    32-byte randomizer from PCZT (little-endian scalar)
 * @param sighash  32-byte transaction sighash (ZIP 244)
 * @param sig_out  64-byte output: R (32 bytes) || S (32 bytes), little-endian
 * @return 0 on success, non-zero on error
 */
int redpallas_sign_digest(const uint8_t* ask, const uint8_t* alpha,
                          const uint8_t* sighash, uint8_t* sig_out);

/**
 * Sign a PCZT spend using its transaction-bound randomized verification key.
 *
 * The caller must independently bind rk to the transaction digest. If rk does
 * not correspond to ask + alpha, the resulting signature cannot verify. This
 * avoids a redundant fixed-base multiplication on the constrained device and
 * leaves only the fixed-schedule secret nonce multiplication in the hot path.
 * Progress reports public work units in the range 0..1000.
 */
int redpallas_sign_digest_for_rk(const uint8_t* ask, const uint8_t* alpha,
                                 const uint8_t* rk, const uint8_t* sighash,
                                 uint8_t* sig_out,
                                 redpallas_progress_callback progress,
                                 void* progress_context);

/**
 * Sign using the cached public ak and verify the host-provided rk first.
 *
 * rk = ak + [alpha]G is derived entirely from public data, avoiding a second
 * secret-scalar multiplication during each signature. The nonce commitment
 * remains on the fixed-schedule implementation. Progress reports fixed public
 * work units in the range 0..1000.
 */
int redpallas_sign_digest_with_ak(const uint8_t* ask, const uint8_t* ak,
                                  const uint8_t* alpha,
                                  const uint8_t* expected_rk,
                                  const uint8_t* sighash, uint8_t* sig_out,
                                  redpallas_progress_callback progress,
                                  void* progress_context);

/** Derive rk = ak + [alpha]G from public Orchard transaction data. */
int redpallas_derive_rk_from_ak(const uint8_t* ak, const uint8_t* alpha,
                                uint8_t* rk_out);

/**
 * Verify a RedPallas signature.
 *
 * @param rk       32-byte randomized verification key (compressed point, LE)
 * @param sighash  32-byte transaction sighash
 * @param sig      64-byte signature: R (32 bytes) || S (32 bytes)
 * @return 0 if signature is valid, non-zero otherwise
 */
int redpallas_verify_digest(const uint8_t* rk, const uint8_t* sighash,
                            const uint8_t* sig);

/**
 * Derive randomized verification key: rk = [(ask + alpha) mod order] * G
 *
 * @param ask    32-byte spend authorizing key (little-endian)
 * @param alpha  32-byte randomizer (little-endian)
 * @param rk_out 32-byte output: compressed point (little-endian x-coordinate)
 * @return 0 on success
 */
int redpallas_derive_rk(const uint8_t* ask, const uint8_t* alpha,
                        uint8_t* rk_out);

/**
 * Scalar multiplication by the Orchard SpendAuth basepoint.
 * Computes res = k * G_spendauth where G_spendauth =
 * GroupHash^P("z.cash:Orchard", "G").
 *
 * @param k    Scalar to multiply (bignum256)
 * @param res  Output point
 */
void redpallas_scalar_mult_spendauth_G(const bignum256* k, curve_point* res);

#endif
