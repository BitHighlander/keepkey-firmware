#ifndef UNITTESTS_FIRMWARE_CLEARSIGN_TEST_CERT_H
#define UNITTESTS_FIRMWARE_CLEARSIGN_TEST_CERT_H

extern "C" {
#include "keepkey/firmware/clearsign_root.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha3.h"
}

#include "gtest/gtest.h"

#include <cstring>
#include <vector>

// A delegate certificate in the layout of clearsign_root.h, signed by
// `root_key` over keccak(0x19 || 0x01 || DOMAIN_SEP || keccak(cert[0..74])),
// the digest EthereumSignTypedHash produces on the root KeepKey.
inline std::vector<uint8_t> rootCert(
    const uint8_t root_key[32], const uint8_t delegate_pubkey[33],
    uint8_t flags = CLEARSIGN_USAGE_MAY_SUPPRESS_RAW, uint32_t scope = 1,
    uint32_t not_after = KK_CLEARSIGN_MIN_EXPIRY + 1,
    const char* alias = "KeepKey Test") {
  std::vector<uint8_t> c(CLEARSIGN_CERT_LEN, 0);
  c[CLEARSIGN_CERT_OFF_VERSION] = CLEARSIGN_CERT_VERSION;
  c[CLEARSIGN_CERT_OFF_FLAGS] = flags;
  for (int i = 0; i < 4; i++) {
    c[CLEARSIGN_CERT_OFF_SCOPE + i] = (uint8_t)(scope >> (24 - 8 * i));
    c[CLEARSIGN_CERT_OFF_EXPIRY + i] = (uint8_t)(not_after >> (24 - 8 * i));
  }
  memcpy(c.data() + CLEARSIGN_CERT_OFF_ALIAS, alias, strlen(alias));
  memcpy(c.data() + CLEARSIGN_CERT_OFF_PUBKEY, delegate_pubkey,
         CLEARSIGN_PUBKEY_LEN);
  const uint8_t domain_sep[32] = CLEARSIGN_DOMAIN_SEPARATOR;
  uint8_t preimage[66] = {0x19, 0x01};
  memcpy(preimage + 2, domain_sep, 32);
  keccak_256(c.data(), CLEARSIGN_CERT_SIGNED_LEN, preimage + 34);
  uint8_t hash[32];
  keccak_256(preimage, sizeof(preimage), hash);
  EXPECT_EQ(
      ecdsa_sign_digest(&secp256k1, root_key, hash,
                        c.data() + CLEARSIGN_CERT_OFF_SIG, nullptr, nullptr),
      0);
  return c;
}

#endif
