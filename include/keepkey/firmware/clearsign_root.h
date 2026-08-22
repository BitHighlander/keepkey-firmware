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

#ifndef KEEPKEY_FIRMWARE_CLEARSIGN_ROOT_H
#define KEEPKEY_FIRMWARE_CLEARSIGN_ROOT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── The KeepKey delegation root ─────────────────────────────────────
 *
 * This translation unit exists so that "who can reach the root key" is a
 * one-line grep. Exactly one function reads it. Adding a second caller is a
 * SECURITY CHANGE, not a refactor, and should be reviewed as one.
 *
 * The root key is what separates 7.16 from 7.15. In 7.15 a describer can
 * mislabel a transaction but cannot conceal it, because the raw review always
 * follows -- which is precisely why 7.15 needs no custody programme. A
 * KeepKey-signed describer MAY omit that review, so the key that vouches for
 * one is the whole trust boundary.
 */

/* Fixed layout. No TLV, no length fields, nothing to fuzz.
 *
 *   off  len  field
 *     0    1  cert_version, must be 0x01
 *     1    1  usage_flags; bit0 = MAY_SUPPRESS_RAW, all other bits MUST be 0
 *     2    4  chain_id, big endian, NONZERO, matched exactly against the tx
 *     6    4  not_after, big endian unix seconds
 *    10   32  alias, NUL-padded ASCII
 *    42   33  delegate_pubkey, compressed secp256k1 (0x02 or 0x03)
 *    75   64  root_sig, compact ECDSA over sha256(TAG || cert[0..74])
 *          = 139
 */
#define CLEARSIGN_CERT_LEN 139
#define CLEARSIGN_CERT_SIGNED_LEN 75
#define CLEARSIGN_CERT_VERSION 0x01
#define CLEARSIGN_USAGE_MAY_SUPPRESS_RAW 0x01

#define CLEARSIGN_CERT_OFF_VERSION 0
#define CLEARSIGN_CERT_OFF_FLAGS 1
#define CLEARSIGN_CERT_OFF_CHAIN 2
#define CLEARSIGN_CERT_OFF_EXPIRY 6
#define CLEARSIGN_CERT_OFF_ALIAS 10
#define CLEARSIGN_CERT_OFF_PUBKEY 42
#define CLEARSIGN_CERT_OFF_SIG 75

#define CLEARSIGN_ALIAS_LEN 32
#define CLEARSIGN_PUBKEY_LEN 33

/* Prepended by the device, NEVER transmitted, so a host can neither substitute
 * nor elide it. It matters because the EVM metadata blob carries no domain tag
 * of its own -- the tag is what guarantees a certificate preimage can never
 * also parse as a metadata payload. Versioned, so a future certificate format
 * cannot be verified by a device that predates it. */
#define CLEARSIGN_DOMAIN_TAG "KeepKeyClearsignDelegate/1"

/* The expiry floor, and the only revocation lever this release has.
 *
 * Set by hand at each release cut and bumped deliberately to revoke. NOT
 * derived from the build date: an auto-moving floor rots test fixtures
 * silently and cannot be reviewed in a diff, and the entire value of this
 * mechanism is that revocation is one reviewable line in a signed release.
 *
 * The consequence, stated plainly because it does not improve by being left
 * implicit: a device that never updates never revokes. */
#define KK_CLEARSIGN_MIN_EXPIRY 1755000000u

/* Verify a delegate certificate against the compiled-in root.
 *
 * Checks, in order: length, version, reserved flag bits, nonzero chain id,
 * expiry against the floor, delegate pubkey prefix, then the signature.
 * Returns false on any failure, and the CALLER degrades to the 7.15 additive
 * path -- never to a refusal. A stale or unverifiable describer is one we no
 * longer trust, and an undescribed transaction is what 7.15 already handles.
 *
 * THE ONLY FUNCTION THAT READS THE ROOT KEY. */
bool clearsign_root_verify_cert(const uint8_t *cert, size_t cert_len);

/* True when the firmware carries no root key at all -- the mechanical 7.15
 * release gate, kept queryable so a test can assert it rather than a human
 * grepping for key bytes. */
bool clearsign_root_is_present(void);

#endif
