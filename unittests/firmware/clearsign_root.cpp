extern "C" {
#include "keepkey/firmware/clearsign_root.h"
}

#include "gtest/gtest.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

// Produced by scripts/ceremony sign_delegate_cert.py --backend file, against
// the untracked TEST root. This fixture is the pipeline's proof: the ceremony
// that will one day run on a KeepKey and the firmware that verifies its output
// were written separately, and this is where they have to agree.
//
//   alias      KeepKey Test
//   chain_id   1
//   not_after  1798761600
//   flags      MAY_SUPPRESS_RAW
const char *kValidCertHex =
    "0101000000016b36ec804b6565704b657920546573740000000000000000000000"
    "00000000000000000002b109ac4f6d75797e4ebb39ffb2a368e18f7228c9d77352"
    "f15b3c15dc2acc57f37f1e87ea6b2681228d5a83807cc8c3c58c95c4fdde98b9bb"
    "be3874db92d7dd6f37009032f2f8f946646801c195ce485b0fabd6a226909564f3"
    "50c991833f064c";

std::vector<uint8_t> unhex(const std::string &h) {
  std::vector<uint8_t> out;
  for (size_t i = 0; i + 1 < h.size(); i += 2)
    out.push_back((uint8_t)strtol(h.substr(i, 2).c_str(), nullptr, 16));
  return out;
}

std::vector<uint8_t> validCert() { return unhex(kValidCertHex); }

}  // namespace

TEST(ClearsignRoot, TheCeremonysCertificateVerifies) {
  // If this fails, the ceremony and the firmware disagree about the preimage,
  // and a real signing session would produce certificates no device accepts.
  auto c = validCert();
  ASSERT_EQ(c.size(), (size_t)CLEARSIGN_CERT_LEN);
  EXPECT_TRUE(clearsign_root_verify_cert(c.data(), c.size()));
}

TEST(ClearsignRoot, RootKeyIsPresentInThisBuild) {
  // The 7.15 release gate is the INVERSE of this: no root key compiled in, so
  // the suppression branch cannot be reached. Queryable so a release test can
  // assert it rather than a human grepping for key bytes.
  EXPECT_TRUE(clearsign_root_is_present());
}

TEST(ClearsignRoot, RejectsAnyMutatedByte) {
  // Every byte of the signed region is covered by the signature. Flipping any
  // one of them must break verification -- not merely the interesting fields.
  auto good = validCert();
  for (size_t i = 0; i < CLEARSIGN_CERT_SIGNED_LEN; i++) {
    auto c = good;
    c[i] ^= 0x01;
    // Version, flags, chain and expiry are rejected before the signature is
    // even checked; the rest fail at the signature. Either way: false.
    EXPECT_FALSE(clearsign_root_verify_cert(c.data(), c.size()))
        << "byte " << i << " was mutated and the certificate still verified";
  }
}

TEST(ClearsignRoot, RejectsAMutatedSignature) {
  auto c = validCert();
  c[CLEARSIGN_CERT_OFF_SIG] ^= 0x01;
  EXPECT_FALSE(clearsign_root_verify_cert(c.data(), c.size()));
}

TEST(ClearsignRoot, RejectsWrongLength) {
  auto c = validCert();
  EXPECT_FALSE(clearsign_root_verify_cert(c.data(), c.size() - 1));
  EXPECT_FALSE(clearsign_root_verify_cert(c.data(), c.size() + 1));
  EXPECT_FALSE(clearsign_root_verify_cert(nullptr, CLEARSIGN_CERT_LEN));
}

TEST(ClearsignRoot, RejectsUnknownVersion) {
  auto c = validCert();
  c[CLEARSIGN_CERT_OFF_VERSION] = 0x02;
  EXPECT_FALSE(clearsign_root_verify_cert(c.data(), c.size()));
}

TEST(ClearsignRoot, RejectsReservedFlagBits) {
  // A flag we do not understand is a capability we never agreed to. Accepting
  // it silently is how a later format grants itself permissions this firmware
  // never reviewed.
  auto c = validCert();
  c[CLEARSIGN_CERT_OFF_FLAGS] = 0x02;
  EXPECT_FALSE(clearsign_root_verify_cert(c.data(), c.size()));
  c[CLEARSIGN_CERT_OFF_FLAGS] = 0x80;
  EXPECT_FALSE(clearsign_root_verify_cert(c.data(), c.size()));
}

TEST(ClearsignRoot, RejectsZeroChainId) {
  // Chain 0 is not a chain. Requiring nonzero means a certificate can never
  // become a wildcard by omission.
  auto c = validCert();
  memset(&c[CLEARSIGN_CERT_OFF_CHAIN], 0, 4);
  EXPECT_FALSE(clearsign_root_verify_cert(c.data(), c.size()));
}

TEST(ClearsignRoot, RejectsExpiryAtOrBelowTheFloor) {
  // The device has no clock, so this is not "is it expired now" but "was it
  // issued for a window this firmware still honours". Bumping the floor in a
  // signed release is the only revocation lever 7.16 has.
  auto c = validCert();
  uint32_t at = KK_CLEARSIGN_MIN_EXPIRY;
  c[CLEARSIGN_CERT_OFF_EXPIRY + 0] = (uint8_t)(at >> 24);
  c[CLEARSIGN_CERT_OFF_EXPIRY + 1] = (uint8_t)(at >> 16);
  c[CLEARSIGN_CERT_OFF_EXPIRY + 2] = (uint8_t)(at >> 8);
  c[CLEARSIGN_CERT_OFF_EXPIRY + 3] = (uint8_t)(at);
  EXPECT_FALSE(clearsign_root_verify_cert(c.data(), c.size()));
}

TEST(ClearsignRoot, RejectsUncompressedOrMalformedDelegateKey) {
  auto c = validCert();
  c[CLEARSIGN_CERT_OFF_PUBKEY] = 0x04;  // uncompressed prefix
  EXPECT_FALSE(clearsign_root_verify_cert(c.data(), c.size()));
  c[CLEARSIGN_CERT_OFF_PUBKEY] = 0x00;
  EXPECT_FALSE(clearsign_root_verify_cert(c.data(), c.size()));
}
