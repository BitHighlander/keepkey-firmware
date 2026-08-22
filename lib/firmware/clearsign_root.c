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

#include "keepkey/firmware/clearsign_root.h"

#include <string.h>

#include "ecdsa.h"
#include "secp256k1.h"
#include "sha2.h"

/* ── The root public key ─────────────────────────────────────────────
 *
 * TEST KEY. Generated 2026-08-21 for bench and ceremony practice, and it must
 * not reach a signed release. The production root will be generated on a
 * KeepKey and will never exist as a file anywhere.
 *
 * An all-zero array here means NO ROOT, which is the 7.15 posture: the
 * suppression branch stays unreachable because nothing can ever verify a
 * certificate. clearsign_root_is_present() exposes that so a release test can
 * assert it rather than a human grepping for key bytes.
 */
static const uint8_t kk_clearsign_root_pubkey[CLEARSIGN_PUBKEY_LEN] = {
    0x02, 0xb1, 0x09, 0xac, 0x4f, 0x6d, 0x75, 0x79, 0x7e, 0x4e, 0xbb,
    0x39, 0xff, 0xb2, 0xa3, 0x68, 0xe1, 0x8f, 0x72, 0x28, 0xc9, 0xd7,
    0x73, 0x52, 0xf1, 0x5b, 0x3c, 0x15, 0xdc, 0x2a, 0xcc, 0x57, 0xf3,
};

bool clearsign_root_is_present(void) {
  for (size_t i = 0; i < CLEARSIGN_PUBKEY_LEN; i++) {
    if (kk_clearsign_root_pubkey[i] != 0x00) return true;
  }
  return false;
}

static uint32_t be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

bool clearsign_root_verify_cert(const uint8_t *cert, size_t cert_len) {
  if (!cert || cert_len != CLEARSIGN_CERT_LEN) return false;
  if (!clearsign_root_is_present()) return false;

  if (cert[CLEARSIGN_CERT_OFF_VERSION] != CLEARSIGN_CERT_VERSION) return false;

  /* Reserved bits must be zero. A flag we do not understand is a capability we
   * did not agree to, and accepting it silently is how a future format grants
   * itself permissions this firmware never reviewed. */
  const uint8_t flags = cert[CLEARSIGN_CERT_OFF_FLAGS];
  if ((flags & (uint8_t)~CLEARSIGN_USAGE_MAY_SUPPRESS_RAW) != 0) return false;

  /* Chain 0 is not a chain. Requiring nonzero means a certificate is always
   * bound to exactly one network and can never be wildcard by omission. */
  if (be32(&cert[CLEARSIGN_CERT_OFF_CHAIN]) == 0) return false;

  /* The device has no clock, so this is not "is it expired now" -- it is "was
   * this issued for a window this firmware still honours". The floor moves
   * only when a signed firmware ships. */
  if (be32(&cert[CLEARSIGN_CERT_OFF_EXPIRY]) <= KK_CLEARSIGN_MIN_EXPIRY)
    return false;

  const uint8_t prefix = cert[CLEARSIGN_CERT_OFF_PUBKEY];
  if (prefix != 0x02 && prefix != 0x03) return false;

  /* sha256(TAG || cert[0..74]). The tag is ours, never the host's. */
  SHA256_CTX ctx;
  uint8_t digest[32];
  sha256_Init(&ctx);
  sha256_Update(&ctx, (const uint8_t *)CLEARSIGN_DOMAIN_TAG,
                strlen(CLEARSIGN_DOMAIN_TAG));
  sha256_Update(&ctx, cert, CLEARSIGN_CERT_SIGNED_LEN);
  sha256_Final(&ctx, digest);

  return ecdsa_verify_digest(&secp256k1, kk_clearsign_root_pubkey,
                             &cert[CLEARSIGN_CERT_OFF_SIG], digest) == 0;
}
