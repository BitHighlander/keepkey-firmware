extern "C" {
#include "keepkey/firmware/contact_book.h"
}

#include "contact_book_vectors.h"
#include "gtest/gtest.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {

std::vector<uint8_t> hex(const char* value) {
  std::vector<uint8_t> out;
  for (size_t i = 0; value[i]; i += 2) {
    unsigned byte = 0;
    sscanf(value + i, "%2x", &byte);
    out.push_back(static_cast<uint8_t>(byte));
  }
  return out;
}

TEST(ContactBook, ParsesBulkRequestAndMatchesHostRoot) {
  const auto request =
      hex("4b4b414252455131010000000703"
          "086569703135353a310114111111111111111111111111111111111111111105416c696365"
          "0a6569703135353a3133370114222222222222222222222222222222222222222203426f62"
          "086569703135353a3101143333333333333333333333333333333333333333054361726f6c");
  const auto expected_root =
      hex("79eb40842fdd0252902ded5888d9267cbd66db8e67de50ef2a34750a42928c65");
  ContactBookManifest manifest{};
  ContactBookEntry entries[CONTACT_BOOK_MAX_ENTRIES]{};
  ASSERT_TRUE(contact_book_parse_request(request.data(), request.size(),
                                         &manifest, entries, nullptr));
  EXPECT_EQ(7u, manifest.revision);
  EXPECT_EQ(3u, manifest.count);
  EXPECT_EQ(0, memcmp(manifest.root, expected_root.data(), 32));
  EXPECT_STREQ("Alice", entries[0].label);
  EXPECT_STREQ("Bob", entries[1].label);
}

TEST(ContactBook, RejectsControlCharactersAndTrailingData) {
  auto request =
      hex("4b4b414252455131010000000101"
          "086569703135353a310114111111111111111111111111111111111111111103426f62");
  ContactBookManifest manifest{};
  ContactBookEntry entries[CONTACT_BOOK_MAX_ENTRIES]{};
  request.back() = '\n';
  EXPECT_FALSE(contact_book_parse_request(request.data(), request.size(),
                                          &manifest, entries, nullptr));
  request.back() = 'b';
  request.push_back(0);
  EXPECT_FALSE(contact_book_parse_request(request.data(), request.size(),
                                          &manifest, entries, nullptr));
}

/* Byte offsets inside a KKABPRF1 proof (see contact_book_process_proof). */
constexpr size_t kCountOffset = 13;
constexpr size_t kRootOffset = 14;
constexpr size_t kSigOffset = 8 + 1 + 4 + 1 + 32 + 33;
constexpr size_t kEntryOffset = kSigOffset + 64;

std::vector<uint8_t> address(const char* hex_address) {
  return hex(hex_address + 2);
}

bool verify(const std::vector<uint8_t>& proof,
            const char* pubkey = ATTESTOR_PUBKEY_ALL) {
  const auto key = hex(pubkey);
  return contact_book_process_proof(proof.data(), proof.size(), key.data());
}

bool matches(const char* network, const std::vector<uint8_t>& destination) {
  return contact_book_match(network, CONTACT_BOOK_DEST_EVM_ADDRESS,
                            destination.data(), destination.size());
}

const auto kAlice = address("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
const auto kBob = address("0x2222222222222222222222222222222222222222");

TEST(ContactBook, VaultRequestRootMatchesTheVault) {
  ContactBookManifest manifest{};
  ContactBookEntry entries[CONTACT_BOOK_MAX_ENTRIES]{};
  auto request = hex(REQ3);
  ASSERT_TRUE(contact_book_parse_request(request.data(), request.size(),
                                         &manifest, entries, nullptr));
  EXPECT_EQ(7u, manifest.revision);
  EXPECT_EQ(3u, manifest.count);
  EXPECT_EQ(hex(ROOT3), std::vector<uint8_t>(manifest.root, manifest.root + 32));
  EXPECT_STREQ("eip155:8453", entries[1].network);
  EXPECT_STREQ("Bob Base", entries[1].label);

  request = hex(REQ16);
  ASSERT_TRUE(contact_book_parse_request(request.data(), request.size(),
                                         &manifest, entries, nullptr));
  EXPECT_EQ(16u, manifest.count);
  request = hex(REQ17);
  EXPECT_FALSE(contact_book_parse_request(request.data(), request.size(),
                                          &manifest, entries, nullptr));
}

TEST(ContactBook, VaultProofsVerifyAndLabelOnlyTheirRecipient) {
  ASSERT_TRUE(verify(hex(PROOF3_0)));
  EXPECT_TRUE(matches("eip155:1", kAlice));
  EXPECT_STREQ("Alice", contact_book_label());
  EXPECT_FALSE(matches("eip155:8453", kAlice)) << "wrong chain";
  EXPECT_FALSE(matches("eip155:1", kBob)) << "wrong address";
  EXPECT_FALSE(contact_book_match("eip155:1", CONTACT_BOOK_DEST_UTXO_SCRIPT,
                                  kAlice.data(), kAlice.size()));

  ASSERT_TRUE(verify(hex(PROOF3_1)));
  EXPECT_TRUE(matches("eip155:8453", kBob));
  EXPECT_STREQ("Bob Base", contact_book_label());
  EXPECT_FALSE(matches("eip155:1", kAlice)) << "a proof replaces the last";

  for (const char* proof : {PROOF3_2, PROOF16_0, PROOF16_15, PROOF5_4,
                            PROOF1_0}) {
    EXPECT_TRUE(verify(hex(proof))) << proof;
  }
  EXPECT_TRUE(matches("eip155:1", kAlice));  // PROOF1_0: depth 0
  contact_book_clear();
  EXPECT_EQ(nullptr, contact_book_label());
  EXPECT_FALSE(matches("eip155:1", kAlice));
}

TEST(ContactBook, RejectsEveryAlteredProof) {
  const auto good = hex(PROOF3_0);
  ASSERT_TRUE(verify(good));
  auto refused = [&](std::vector<uint8_t> proof, const char* why) {
    EXPECT_FALSE(verify(proof)) << why;
    EXPECT_EQ(nullptr, contact_book_label()) << why;
    ASSERT_TRUE(verify(good));
  };
  auto bad = good;
  bad[kSigOffset + 5] ^= 1;
  refused(bad, "root signature");
  bad = good;
  bad[kRootOffset] ^= 1;
  refused(bad, "root");
  bad = good;
  /* entry: len, "eip155:1", type, len, address, len, "Alice" */
  bad[kEntryOffset + 1 + 8 + 2 + 20 + 1] = 'a';
  refused(bad, "label");
  bad = good;
  bad[kEntryOffset + 1 + 8 + 2] ^= 1;
  refused(bad, "address");
  bad = good;
  bad[kEntryOffset + 8] = '5';
  refused(bad, "network");
  bad = good;
  bad[kCountOffset] = 17;
  refused(bad, "more than 16 contacts");
  bad = good;
  bad.push_back(0);
  refused(bad, "trailing data");
  bad = good;
  bad.pop_back();
  refused(bad, "truncated sibling");
  bad = good;
  bad[kEntryOffset + 1 + 8 + 2 + 20 + 1 + 5] = 3;
  refused(bad, "index out of range");
  bad = good;
  bad[0] = 'X';
  refused(bad, "magic");

  /* A certification made by another wallet's attestor key (a passphrase
   * session derives a different one) never labels this wallet's sends. */
  EXPECT_TRUE(verify(hex(PROOF3_0_OTHER_KEY), OTHER_PUBKEY)) << "control";
  EXPECT_FALSE(verify(hex(PROOF3_0_OTHER_KEY)));
  EXPECT_FALSE(verify(good, OTHER_PUBKEY));
  EXPECT_EQ(nullptr, contact_book_label());
}

}  // namespace
