// gtest first: confirm_sm.h defines an isprint() macro that collides with the
// standard library's declaration if the C++ headers are pulled in after it.
#include "gtest/gtest.h"

#include <cstring>
#include <string>

extern "C" {
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/font.h"
#include "keepkey/board/layout.h"
}

TEST(Board, Shutdown) {
  EXPECT_EXIT(shutdown(), ::testing::ExitedWithCode(1), "");
}

// Exactly BODY_ROWS rows of body text fit on the display: the body starts at
// TOP_MARGIN + font_height + BODY_TOP_MARGIN and advances by font_height +
// BODY_FONT_LINE_PADDING, so row 4 begins at y=66 on a 64px-tall screen and
// draw_char_with_shift() refuses to draw it. Nothing announces that -
// draw_string() simply stops - so a body of BODY_ROWS+1 rows loses its tail
// silently. confirm_helper() pages such bodies instead; these are the
// properties that split has to hold.
namespace {

constexpr uint32_t kRows = BODY_ROWS;
constexpr uint16_t kWidth = BODY_WIDTH;

// Real bodies from ethereum.c's layoutEthereumConfirmTx(). All four sit within
// a few characters of the limit, which is why the overflow is value-dependent
// and went unnoticed: swap wstETH for ETH, or 1000000 for 1, and it fits.
const char *const kOverflowing[] = {
    // "Unlock full %s balance for withdrawal by %s?"
    "Unlock full wstETH balance for withdrawal by "
    "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984?",
    // "Approve withdrawal of up to %s by %s?"
    "Approve withdrawal of up to 1000000 USDC by "
    "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984?",
    "Approve withdrawal of up to 0.000000000000000001 ETH by "
    "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984?",
};

const char *const kFitting[] = {
    "Send 1.5 ETH to 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",
    "Remove ability for 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984 to withdraw "
    "USDC?",
};

// Walks confirm_body_split() exactly as confirm_helper() does: count, then
// fetch each page by index.
std::string JoinPages(const char *body, size_t *pages) {
  *pages = confirm_body_split(body, kWidth, 0, NULL);
  EXPECT_GT(*pages, 0u) << "|" << body << "| could not be split";

  std::string joined;
  for (size_t i = 0; i < *pages; i++) {
    char page[BODY_CHAR_MAX];
    EXPECT_EQ(confirm_body_split(body, kWidth, i, page), *pages);
    EXPECT_LE(calc_str_line(get_body_font(), page, kWidth), kRows)
        << "page " << (i + 1) << " of |" << body << "| still overflows";
    joined += page;
  }
  return joined;
}

}  // namespace

// The bug: these bodies do not fit, so today they are drawn in part.
TEST(Board, ConfirmBodiesThatOverflowAreDetected) {
  for (const char *body : kOverflowing) {
    EXPECT_GT(calc_str_line(get_body_font(), body, kWidth), kRows)
        << "|" << body << "| no longer overflows; pick a new vector rather "
        << "than deleting this case";
  }
}

// The fix: paging discloses every character. Dropping the ERC-20 spender's
// last three hex digits is what lets a look-alike address pass review.
TEST(Board, ConfirmPagesDiscloseTheWholeBody) {
  for (const char *body : kOverflowing) {
    size_t pages = 0;
    EXPECT_EQ(JoinPages(body, &pages), std::string(body));
    EXPECT_GT(pages, 1u) << "|" << body << "| should have been split";
  }
}

// And bodies that already fit keep their single screen — pagination must not
// add a press to the flows that were never broken.
TEST(Board, ConfirmFittingBodiesAreNotPaged) {
  for (const char *body : kFitting) {
    ASSERT_LE(calc_str_line(get_body_font(), body, kWidth), kRows) << body;
    size_t pages = 0;
    EXPECT_EQ(JoinPages(body, &pages), std::string(body));
    EXPECT_EQ(pages, 1u) << "|" << body << "| was split unnecessarily";
  }
}

// calc_crc32() is what storage_commit() uses to decide a flash write survived,
// so the emulator has to compute what the STM32 peripheral computes. It did
// not: it ran a reflected zlib CRC-32 over word_len *bytes*, meaning a 643-word
// buffer was covered as 643 bytes. The storage suite could not tell a correct
// length from a truncated one, which is precisely the bug the V17 CRC fix was
// about.
//
// These vectors are CRC-32/MPEG-2 (poly 0x04C11DB7, init 0xFFFFFFFF, no
// reflection, no final XOR) over each word's big-endian bytes — what the
// peripheral produces for `CRC_DR = word`. Reading the buffer as uint32_t
// rather than as bytes keeps this independent of host endianness.
TEST(Board, Crc32MatchesTheStm32Peripheral) {
  const uint32_t one[] = {0x12345678};  // bytes 12 34 56 78
  EXPECT_EQ(0xDF8A8A2Bu, calc_crc32(one, 1));

  const uint32_t two[] = {0x12345678, 0x9ABCDEF0};  // ... 9A BC DE F0
  EXPECT_EQ(0x7D24A31Bu, calc_crc32(two, 2));
}

// storage_commit() marshals a 2572-byte buffer — 643 words — holding a 2569-byte
// V17 record, so the last meaningful byte is index 2568. It reaches
// storage_wipe() when the CRC disagrees, so a byte outside the CRC is a byte
// whose corruption surfaces later as a decrypt failure instead.
TEST(Board, Crc32CoversTheFinalByteOfTheV17Record) {
  alignas(uint32_t) uint8_t buf[2572] = {};
  const uint32_t clean643 = calc_crc32(buf, 643);
  const uint32_t clean642 = calc_crc32(buf, 642);

  buf[2568] = 0x01;

  EXPECT_NE(clean643, calc_crc32(buf, 643)) << "byte 2568 is outside the CRC";
  // The regression itself: at sizeof(flash_temp)==2570 the integer division
  // gave 642 words = 2568 bytes, and byte 2568 changed nothing.
  EXPECT_EQ(clean642, calc_crc32(buf, 642));
}
