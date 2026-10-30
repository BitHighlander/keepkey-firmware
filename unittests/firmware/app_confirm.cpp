extern "C" {
#include "keepkey/firmware/app_confirm.h"
}
#include "gtest/gtest.h"
#include "test_board.h"
#include <string>

TEST(AppConfirm, AllByteValuesHaveAnUnambiguousVisibleRepresentation) {
  for (unsigned value = 0; value < 256; ++value) {
    const uint8_t byte = value;
    char actual[5];
    char expected[5];
    if (value >= 0x21 && value <= 0x7e && value != 0x5c) {
      expected[0] = value;
      expected[1] = 0;
    } else {
      snprintf(expected, sizeof(expected), "\\x%02X", value);
    }
    ASSERT_TRUE(confirm_bytes_escape(&byte, 1, actual, sizeof(actual)));
    EXPECT_STREQ(expected, actual) << value;
  }
}

TEST(AppConfirm, PagesPreserveEveryEscapedByteIncludingHiddenSuffix) {
  kk_test_board_init();
  const std::string input = std::string(200, 'A') + "\n\t\\x00TAIL0199";
  char escaped[1024];
  ASSERT_TRUE(
      confirm_bytes_escape(reinterpret_cast<const uint8_t*>(input.data()),
                           input.size(), escaped, sizeof(escaped)));
  std::string joined;
  size_t offset = 0;
  unsigned pages = 0;
  while (offset < input.size()) {
    char page[128];
    size_t take = confirm_bytes_format_page(
        reinterpret_cast<const uint8_t*>(input.data() + offset),
        input.size() - offset, page, sizeof(page));
    ASSERT_GT(take, 0u);
    offset += take;
    joined += page;
    pages++;
  }
  EXPECT_GT(pages, 1u);
  EXPECT_EQ(escaped, joined);
  EXPECT_NE(std::string::npos, joined.find("TAIL0199"));
}

static bool is_text(const std::string& s) {
  return confirm_is_text(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

TEST(AppConfirm, TextIsPrintableUtf8) {
  EXPECT_TRUE(is_text(""));
  EXPECT_TRUE(is_text("Hello, world!"));
  EXPECT_TRUE(is_text(
      "app.safe.global wants you to sign in with your Ethereum account:\n"
      "0x73d0385F4d8E00C5e6504C6030F47BF6212736A8\r\n\tURI: x"));
  EXPECT_TRUE(is_text("caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x94\x91"));
  EXPECT_TRUE(is_text("\xc2\xa0\xef\xbf\xbd\xf4\x8f\xbf\xbf"));
  // 0x-prefixed ASCII is text: the title, not the body, tells it apart.
  EXPECT_TRUE(is_text("0xa15d670d"));
}

TEST(AppConfirm, BytesThatAreNotTextAreBinary) {
  // The real Safe safeTxHash from leg G12: starts with a continuation byte.
  const std::string hash =
      "\xa1\x5d\x67\x0d\x17\x62\x17\x51\xbb\x88\xf4\x93\xf8\xb3\x05\xc5"
      "\xbd\xe4\xee\xaa\x7a\xa4\xf9\x87\x5d\xa4\xd9\xbd\x2f\xad\x39\xb0";
  EXPECT_FALSE(is_text(hash));
  EXPECT_FALSE(is_text(std::string("a\0b", 3)));  // NUL
  EXPECT_FALSE(is_text("a\x1b[2Jb"));             // escape sequence
  EXPECT_FALSE(is_text("a\x7f"));                 // DEL
  EXPECT_FALSE(is_text("\x80"));                  // lone continuation
  EXPECT_FALSE(is_text("\xc3"));                  // truncated
  EXPECT_FALSE(is_text("\xe2\x82"));              // truncated
  EXPECT_FALSE(is_text("\xc3\x28"));              // bad continuation
  EXPECT_FALSE(is_text("\xc0\xaf"));              // overlong '/'
  EXPECT_FALSE(is_text("\xe0\x80\xaf"));          // overlong
  EXPECT_FALSE(is_text("\xf0\x80\x80\xaf"));      // overlong
  EXPECT_FALSE(is_text("\xed\xa0\x80"));          // surrogate
  EXPECT_FALSE(is_text("\xf4\x90\x80\x80"));      // above U+10FFFF
  EXPECT_FALSE(is_text("\xf8\x88\x80\x80\x80"));  // 5-byte form
  EXPECT_FALSE(is_text("\xc2\x85"));              // C1 control (NEL)
}
