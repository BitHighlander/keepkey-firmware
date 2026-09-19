extern "C" {
#include "keepkey/firmware/clearsign_root.h"
}

#include "gtest/gtest.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

// Signed ON A KEEPKEY by sign_delegate_cert.py --backend keepkey, against a
// root seed generated on the device itself -- the production ceremony shape,
// where the root key never exists as a file anywhere.
//
// This fixture is the pipeline's proof. The ceremony and the firmware verifier
// were written separately, and this is where they have to agree; they did not,
// once. The root signs via EthereumSignTypedHash, so the preimage below is
// keccak(0x19||0x01||DOMAIN_SEP||keccak(cert[0..74])) and NOT a bare sha256
// tag -- that mismatch is exactly what this fixture exists to catch.
//
//   alias      KeepKey
//   chain_id   1
//   not_after  1818806400
//   flags      MAY_SUPPRESS_RAW
const char *kValidCertHex =
    "0101000000016c68c8804b6565704b6579000000000000000000000000000000"
    "000000000000000000000289265fa1eeb7482b853f8181d15a56c412ab0c9671"
    "51613dc43a58a5437dae9a6b51f1f887311e1eaee5d36d302d6f1a09055e25ea"
    "1afe68565a0bb73b9622f52f56bbb60a8c1a3cc17e70e53aff2b99bb7430f92a"
    "1bcb28e4cb6503ef7b46e7";

// The Solana suite's scope-501 certificate (kCert501Hex in solana.cpp,
// python-keepkey's CERT_501), signed by the same root over a different body.
//
//   alias      KeepKey Vault
//   chain_id   501
//   not_after  1818806400
//   flags      MAY_SUPPRESS_RAW
const char *kCert501Hex =
    "0101000001f56c68c8804b6565704b6579205661756c74000000000000000000"
    "000000000000000000000342f5f9704494b3f9bd72295eecaf29d783d23ea02b"
    "2dc9f48abcd2e46d4850cfa2753fac6068a45747a32a4a39f249af72b55370f3"
    "491913b7fb9a80207d619b3b4fca6750fc1fdc790da5562b42a351e12cde3c0f"
    "084056a24ca8d1bf2c36b5";

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

TEST(ClearsignRoot, DelegateExtractionRequiresTheSignedScopeAndCapability) {
  auto c = validCert();
  uint8_t delegate[CLEARSIGN_PUBKEY_LEN] = {0};
  char alias[CLEARSIGN_ALIAS_LEN + 1] = {0};
  ASSERT_TRUE(clearsign_root_cert_delegate(c.data(), c.size(), 1, delegate,
                                          alias));
  EXPECT_STREQ(alias, "KeepKey");
  EXPECT_TRUE(delegate[0] == 0x02 || delegate[0] == 0x03);
  EXPECT_FALSE(clearsign_root_cert_delegate(c.data(), c.size(), 501, delegate,
                                           alias));
}

TEST(ClearsignRoot, SevenSixteenAlwaysShipsTheRoot) {
  // Vault turns certified ClearSign on from the firmware version alone
  // (>= 7.16.0). A 7.16+ build without the root would refuse every
  // certificate Vault sends, so the version and the root move together.
  const bool certified_by_version =
      MAJOR_VERSION > 7 || (MAJOR_VERSION == 7 && MINOR_VERSION >= 16);
  EXPECT_TRUE(!certified_by_version || clearsign_root_is_present())
      << "firmware " << MAJOR_VERSION << "." << MINOR_VERSION
      << " ships without a ClearSign root";
}

TEST(ClearsignRoot, TheEmbeddedRootIsTheAlphaRoot) {
  // Pins the embedded root to exactly the alpha root,
  // 02de9231b2094433235532fb1932e324a2c7304195e12e610c675cccbbd606dae7
  // (the marked root KeepKey, device 393137350D4736341B003900), without a
  // second reader of the key: clearsign_root_verify_cert stays the only
  // function that reads it.
  //
  // One certificate is not enough. An ECDSA signature verifies under two
  // public keys, one for each point R with x(R) = r, so kValidCertHex alone
  // also verifies under 0389126d...0c94e9. kCert501Hex's other key is
  // 02d6c172...c720bd. The alpha root is the only key both verify under.
  //
  // A production root replaces these bytes, and both fixtures are re-minted
  // by it, in one change (docs/ClearsignRootCeremony.md 4.4).
  auto a = validCert();
  auto b = unhex(kCert501Hex);
  ASSERT_EQ(b.size(), (size_t)CLEARSIGN_CERT_LEN);
  EXPECT_TRUE(clearsign_root_verify_cert(a.data(), a.size()));
  EXPECT_TRUE(clearsign_root_verify_cert(b.data(), b.size()));
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
  memset(&c[CLEARSIGN_CERT_OFF_SCOPE], 0, 4);
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
