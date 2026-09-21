extern "C" {
#include "keepkey/firmware/contact_book.h"
}

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

}  // namespace
