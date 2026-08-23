extern "C" {
#include "keepkey/board/font.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/firmware/reset.h"
#include "trezor/crypto/bip39_english.h"
}

#include "gtest/gtest.h"

#include <cstdio>
#include <cstring>
#include <string>

// The seed backup and BIP-85 display are drawn by
// layout_constant_power_notification(), which starts at x = 128 + LEFT_MARGIN
// because the display driver mirrors the right half of the canvas onto the
// panel. Only KEEPKEY_DISPLAY_WIDTH - (128 + LEFT_MARGIN) px exists past that
// origin -- not BODY_WIDTH.
//
// Packing against BODY_WIDTH (225) fit words onto a page the renderer then ran
// off the edge of, silently: draw_char_impl() rejects the first glyph crossing
// 256, draw_string_walk() stops, and everything after it is dropped with no
// ellipsis and no indicator. Measured over 200,000 random 24-word mnemonics
// with the real font tables, 1.712% of backups clipped and 0.646% never showed
// one of the words at all.
//
// These tests pin the arithmetic the fix depends on, using the real font
// metrics rather than a model of them.

namespace {

int TextWidth(const Font *font, const char *s) {
  int w = 0;
  for (; *s; s++) w += font_get_char(font, *s)->width;
  return w;
}

}  // namespace

// The budget is derived from the real draw origin, not asserted as a literal.
TEST(SeedDisplay, ConstantPowerBudgetIsDerivedFromTheDrawOrigin) {
  EXPECT_EQ(CONSTANT_POWER_BODY_WIDTH,
            KEEPKEY_DISPLAY_WIDTH - (128 + LEFT_MARGIN));
  EXPECT_EQ(CONSTANT_POWER_BODY_WIDTH, 124)
      << "if the origin or canvas width changes this must be re-derived, not "
         "patched to match";
  EXPECT_LT(CONSTANT_POWER_BODY_WIDTH, BODY_WIDTH)
      << "the whole defect was measuring against the larger of these two";
}

// EXHAUSTIVE over every BIP-39 word and every index a 24-word backup can use.
// Not a sample: the failure mode is a handful of maximum-width words, and a
// random sample says ~100% of pairs fit while the worst case still overflows.
TEST(SeedDisplay, EveryNumberedWordFitsOnOneLine) {
  const Font *body = get_body_font();
  int widest = 0;
  char widest_text[64] = {0};

  for (int idx = 1; idx <= MAX_WORDS; idx++) {
    for (int w = 0; wordlist[w]; w++) {
      char buf[64];
      snprintf(buf, sizeof(buf), "%d.%s", idx, wordlist[w]);
      const int px = TextWidth(body, buf);
      if (px > widest) {
        widest = px;
        snprintf(widest_text, sizeof(widest_text), "%s", buf);
      }
      ASSERT_LE(px, CONSTANT_POWER_BODY_WIDTH)
          << "\"" << buf << "\" is " << px << " px and cannot be shown at all";
    }
  }
  EXPECT_LE(widest, CONSTANT_POWER_BODY_WIDTH)
      << "widest numbered word is \"" << widest_text << "\" at " << widest
      << " px";
}

// The design fact that forces one word per line in the worst case. If this ever
// starts passing, two-up packing became possible and the extra pages can go.
TEST(SeedDisplay, TwoNumberedWordsDoNotAlwaysFitOneLine) {
  const Font *body = get_body_font();
  int widest_at[MAX_WORDS + 1];
  char widest_txt[MAX_WORDS + 1][32];
  memset(widest_at, 0, sizeof(widest_at));

  for (int idx = 1; idx <= MAX_WORDS; idx++)
    for (int w = 0; wordlist[w]; w++) {
      char buf[64];
      snprintf(buf, sizeof(buf), "%d.%s", idx, wordlist[w]);
      const int px = TextWidth(body, buf);
      if (px > widest_at[idx]) {
        widest_at[idx] = px;
        snprintf(widest_txt[idx], sizeof(widest_txt[idx]), "%s", buf);
      }
    }

  int worst = 0, worst_idx = 1;
  for (int i = 1; i < MAX_WORDS; i += 2) {
    const int pair = widest_at[i] + widest_at[i + 1];
    if (pair > worst) {
      worst = pair;
      worst_idx = i;
    }
  }

  // Even with NO separator at all. Trimming indentation cannot rescue this.
  EXPECT_GT(worst, CONSTANT_POWER_BODY_WIDTH)
      << "widest adjacent pair " << widest_txt[worst_idx] << " + "
      << widest_txt[worst_idx + 1] << " is " << worst << " px against a "
      << CONSTANT_POWER_BODY_WIDTH << " px budget";

  const int space_px = font_get_char(body, ' ')->width;
  EXPECT_GT(worst + space_px, CONSTANT_POWER_BODY_WIDTH);
  EXPECT_GT(worst + 3 * space_px, CONSTANT_POWER_BODY_WIDTH)
      << "the historical 3-space separator";
}

// GROUPING, not subpaging, is what MAX_PAGES bounds.
//
// The earlier version of this test packed at CONSTANT_POWER_BODY_WIDTH and
// compared the result to MAX_PAGES. That was stale the moment the design
// changed: groups are formed at BODY_WIDTH -- because the grouping is the host
// protocol boundary, one ButtonRequest per group -- and the 124 px fitting
// happens as subpages INSIDE a group, which consume no page slots. Comparing
// physical subpages against MAX_PAGES compared two different things and would
// have failed for the wrong reason.
TEST(SeedDisplay, WorstCaseMnemonicGroupsWithinMaxPages) {
  const Font *body = get_body_font();

  const char *widest_word = "";
  int widest = 0;
  for (int w = 0; wordlist[w]; w++) {
    const int px = TextWidth(body, wordlist[w]);
    if (px > widest) {
      widest = px;
      widest_word = wordlist[w];
    }
  }

  // Reproduce the GROUPING rule: reset.c packs at BODY_WIDTH, unchanged.
  std::string page;
  int groups = 1;
  for (int i = 0; i < MAX_WORDS; i++) {
    char word[64];
    snprintf(word, sizeof(word), (i & 1) ? "%d.%s\n" : "%d.%s", i + 1,
             widest_word);
    std::string cand = page + "   " + word;
    if (calc_str_line(body, cand.c_str(), BODY_WIDTH) > 3) {
      groups++;
      cand = std::string("   ") + word;
    }
    page = cand;
  }

  EXPECT_LE(groups, MAX_PAGES)
      << "an all-\"" << widest_word << "\" mnemonic forms " << groups
      << " groups but MAX_PAGES is " << MAX_PAGES;
  EXPECT_EQ(MAX_PAGES, 6)
      << "MAX_PAGES must stay at the legacy value: raising it was the approach "
         "that changed the host ButtonRequest count";
}

// The known clipping vector from the finding. Under the old 225px packing this
// page was accepted and then clipped; at the real width it wraps instead.
TEST(SeedDisplay, KnownClippingVectorWrapsInsteadOfOverflowing) {
  const Font *body = get_body_font();
  static const char kClipped[] = "   22.second\n   23.together   24.observe\n";

  // It does not fit three lines at the real width -- so the packer splits it,
  // which is precisely what stops the renderer dropping "e" off "24.observe".
  EXPECT_GT(calc_str_line(body, kClipped, CONSTANT_POWER_BODY_WIDTH), 3u)
      << "this vector must be recognised as not fitting one page";

  // And it WOULD have been accepted under the old, wrong width.
  EXPECT_LE(calc_str_line(body, kClipped, BODY_WIDTH), 3u)
      << "if this fails the vector no longer demonstrates the original bug";
}
