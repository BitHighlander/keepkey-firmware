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
#include "trezor/crypto/sha3.h"

/* ── The root public key ─────────────────────────────────────────────
 *
 * A RELEASE BUILD SHIPS NO ROOT. The array is all-zero unless the build
 * explicitly asks for a test key, which is the 7.15 posture carried forward:
 * with no root, no certificate can ever verify, so the suppression branch is
 * unreachable rather than merely unused. clearsign_root_is_present() exposes
 * that so a release test asserts it instead of a human grepping key bytes.
 *
 * The real root will be generated on a KeepKey, will never exist as a file,
 * and gets pasted in at the release cut as a reviewable one-line diff. Making
 * the DEFAULT empty means forgetting that step produces a device that
 * clear-signs nothing -- the safe failure -- rather than one that trusts a key
 * whose private half sits in a scratch directory.
 */
#if defined(KK_CLEARSIGN_TEST_ROOT)
/* TEST KEY, unit tests and bench only. Generated 2026-08-21 on a marked
 * KeepKey the way the production root will be -- seed generated on the device,
 * never exported -- so the only thing that changes for the real ceremony is
 * which device runs it. m/44'/60'/0'/0/0, device 393137350D4736341B003900,
 * reseeded 2026-08-21 for the second rehearsal. */
static const uint8_t kk_clearsign_root_pubkey[CLEARSIGN_PUBKEY_LEN] = {
    0x02, 0xde, 0x92, 0x31, 0xb2, 0x09, 0x44, 0x33, 0x23, 0x55, 0x32,
    0xfb, 0x19, 0x32, 0xe3, 0x24, 0xa2, 0xc7, 0x30, 0x41, 0x95, 0xe1,
    0x2e, 0x61, 0x0c, 0x67, 0x5c, 0xcc, 0xbb, 0xd6, 0x06, 0xda, 0xe7,
};
#else
static const uint8_t kk_clearsign_root_pubkey[CLEARSIGN_PUBKEY_LEN] = {0};
#endif

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

  /* keccak(0x19 || 0x01 || DOMAIN_SEP || keccak(cert[0..74])).
   *
   * Byte for byte what EthereumSignTypedHash produces, so the root can be an
   * ordinary KeepKey. The domain separator is ours and never crosses the
   * wire. */
  static const uint8_t domain_sep[32] = CLEARSIGN_DOMAIN_SEPARATOR;
  struct SHA3_CTX ctx;
  uint8_t digest[32];

  sha3_256_Init(&ctx);
  sha3_Update(&ctx, cert, CLEARSIGN_CERT_SIGNED_LEN);
  keccak_Final(&ctx, digest);

  const uint8_t prefix712[2] = {0x19, 0x01};
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, prefix712, sizeof(prefix712));
  sha3_Update(&ctx, domain_sep, sizeof(domain_sep));
  sha3_Update(&ctx, digest, sizeof(digest));
  keccak_Final(&ctx, digest);

  return ecdsa_verify_digest(&secp256k1, kk_clearsign_root_pubkey,
                             &cert[CLEARSIGN_CERT_OFF_SIG], digest) == 0;
}
