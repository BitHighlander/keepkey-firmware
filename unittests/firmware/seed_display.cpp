// Include order matters here, and this mirrors unittests/board/board.cpp
// exactly because that file already gets it right.
//
// C++ standard headers FIRST: the board headers pull in <ctype.h>, and having
// that inside extern "C" before <string>/gtest have set up the C++ <cctype>
// machinery breaks the build. That is precisely how this file first failed the
// emulator job while ARM stayed green -- ARM does not compile unit tests.
//
// The board headers still need extern "C": none of them carry __cplusplus
// guards, so without it they would get C++ linkage and fail to link against the
// C-compiled firmware objects.
#include "gtest/gtest.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

extern "C" {
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/font.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/timer.h"
#include "keepkey/firmware/reset.h"
#include "trezor/crypto/bip39_english.h"
}

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

// confirm_body_fits_constant_power() asks the real renderer, so it needs the
// canvas the renderer draws into.
//
// timer_init() is required and cannot be dropped: it fills free_queue, and
// layout_init() calls post_periodic(), which does runnable_queue_pop(&free_queue)
// and dereferences the result with no NULL check. Without timer_init() that is a
// null dereference, not merely a missing tick.
//
// timer_init() is also what arms the 1 kHz SIGALRM (ualarm(1000, 1000)), so it
// is disarmed immediately afterwards. No signal() call and no TearDown: this
// fixture neither installs SIG_IGN process-wide nor restores a handler, so it
// cannot leak state into the rest of the binary in either direction.
void EnsureCanvas() {
  static bool ready = false;
  if (!ready) {
    timer_init();
    layout_init(display_canvas_init());
    ualarm(0, 0);
    ready = true;
  }
}

int TextWidth(const Font *font, const char *s) {
  int w = 0;
  for (; *s; s++) w += font_get_char(font, *s)->width;
  return w;
}

}  // namespace

namespace {

// Internal linkage: unittests/board/board.cpp defines its own BodyFits fixture,
// and two different class definitions sharing one external name is an ODR
// violation even when they happen to land in separate binaries today. The name
// is distinct AND the linkage is internal, so neither can bite later.
class SeedDisplayBodyFits : public ::testing::Test {
 protected:
  void SetUp() override { EnsureCanvas(); }
};

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

// The subpage splitter is where per-subpage content is proven.
//
// The carried subpages inside a group are drawn but not waited on, so the
// message loop never runs between them and DebugLinkGetState cannot observe
// them individually -- a DebugLink screenshot sees a group's LAST subpage only.
// Evidence for what each subpage contains therefore comes from here and from
// physical OLED capture, never from assumed DebugLink screenshots.
TEST_F(SeedDisplayBodyFits, SubpagesCoverEveryRowExactlyOnceInOrder) {
  // A group as reset.c formats one: rows are newline separated, two numbered
  // words per row, leading indent on each row.
  static const char kGroup[] =
      "   1.mushroom   2.mushroom\n"
      "   3.mushroom   4.mushroom\n"
      "   5.mushroom   6.mushroom\n";

  std::string reassembled;
  const char *p = kGroup;
  int subpages = 0;
  while (*p) {
    const size_t take = confirm_constant_power_subpage_take(p);
    ASSERT_GT(take, 0u) << "splitter must always make progress";
    ASSERT_LE(take, strlen(p));

    std::string chunk(p, take);
    // A subpage must never end mid-row: it ends at a newline or at the body end.
    ASSERT_TRUE(chunk.back() == '\n' || take == strlen(p))
        << "subpage split inside a row: \"" << chunk << "\"";
    // And it must actually fit, measured by the renderer.
    EXPECT_TRUE(confirm_body_fits_constant_power(chunk.c_str(),
                                                 CONSTANT_POWER_BODY_WIDTH))
        << "subpage does not fit: \"" << chunk << "\"";

    reassembled += chunk;
    p += take;
    // No leading-space skip: the pager preserves indentation, so the chunks
    // must reassemble to the group BYTE FOR BYTE. Skipping spaces here while
    // production stripped them would have hidden exactly that divergence.
    subpages++;
    ASSERT_LT(subpages, 32) << "splitter failed to terminate";
  }

  // Every row appears exactly once and in order.
  EXPECT_EQ(reassembled, std::string(kGroup))
      << "subpages must reassemble to the group with nothing lost, duplicated "
         "or reordered";
  // The vector must actually CROSS a subpage boundary, or this test proves
  // nothing about splitting: a single-subpage body reassembles trivially.
  EXPECT_GT(subpages, 1)
      << "the mushroom vector must need more than one subpage at "
      << CONSTANT_POWER_BODY_WIDTH << " px, otherwise this regression is inert";
}

// A row that cannot fit must be REJECTED, not shown clipped.
//
// The splitter proves the row does not fit and then must refuse: returning it
// anyway would render clipped content while the pager reported success -- the
// exact failure this change exists to remove. Fail closed.
TEST_F(SeedDisplayBodyFits, UnsplittableRowIsRejectedRatherThanClipped) {
  // Four widest numbered words on one row: far past the 124 px budget, and
  // there is no row boundary inside it to split on.
  const std::string wide =
      "   1.mushroom   2.mushroom   3.mushroom   4.mushroom\n";
  ASSERT_FALSE(confirm_body_fits_constant_power(wide.c_str(),
                                                CONSTANT_POWER_BODY_WIDTH))
      << "precondition: this row must genuinely not fit";

  EXPECT_EQ(confirm_constant_power_subpage_take(wide.c_str()), 0u)
      << "a row that cannot be shown in full must be refused, not returned for "
         "display; the pager treats 0 as failure and declines to sign";
}
