extern "C" {
#include "keepkey/board/layout.h"
#include "keepkey/emulator/setup.h"
#include "keepkey/firmware/app_layout.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/recovery_cipher.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/signing.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/rand/rng_health.h"
#include "trezor/crypto/bip39_english.h"
}

#include "gtest/gtest.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);
bool kkconfirm_sendTiny(uint16_t msgId, const uint8_t* payload, uint8_t len);

extern "C" bool keepkey_before_message_dispatch(MessageType msg_id);
extern "C" void recovery_review_reset_cipher_draws(void);
extern "C" unsigned recovery_review_cipher_draws(void);

static void ensure_recovery_storage_ready(void) {
  static bool ready = false;
  if (!ready) {
    setup();
    storage_init();
    ready = true;
  }
}

TEST(Recovery, ExactStrMatch) {
  char LHS[] = "allow\0";
  char RHS[] = "all\0";

  ASSERT_TRUE(exact_str_match(LHS, RHS, 1));
  ASSERT_TRUE(exact_str_match(LHS, RHS, 2));
  ASSERT_TRUE(exact_str_match(LHS, RHS, 3));
  ASSERT_FALSE(exact_str_match(LHS, RHS, 4));
}

bool attempt_auto_complete(char *partial_word);

TEST(Recovery, AutoComplete) {
  char partial_word[] = "all\0\0\0\0\0";
  ASSERT_TRUE(attempt_auto_complete(partial_word));
  ASSERT_TRUE(memcmp(partial_word, "all\0\0\0\0\0", sizeof(partial_word)) == 0);

  memcpy(partial_word, "allo\0\0\0\0", sizeof(partial_word));
  ASSERT_TRUE(attempt_auto_complete(partial_word));
  ASSERT_TRUE(memcmp(partial_word, "allow\0\0\0", sizeof(partial_word)) == 0);

  memcpy(partial_word, "allways\0", sizeof(partial_word));
  ASSERT_FALSE(attempt_auto_complete(partial_word));
  ASSERT_TRUE(memcmp(partial_word, "allways\0", sizeof(partial_word)) == 0);
}

TEST(Recovery, WordlistLengths) {
  for (int i = 0; wordlist[i]; i++) {
    const char *word = wordlist[i];
    size_t len = strlen(word);
    for (int c = len; c <= BIP39_MAX_WORD_LEN; c++) {
      ASSERT_EQ(word[c], '\0') << "bip39 word list must be padded";
    }
  }
}

// Regression coverage for #584 (alpha's backspace tests). alpha fixed it with a
// raw-byte mirror (coded_mnemonic); the audited 7.15 assembly fixes it with
// coded_word_unknown / resync_current_word_after_delete() and has no such
// mirror, so these tests keep every behavioural assertion (plaintext state,
// armed ceremony, raw-prefix detection) and drop the coded_mnemonic ones.
// The delete-resync unit contract itself is pinned by
// DeleteKeepsTypedCipherCharactersNotTheCurrentMapping. These tests drive recovery_character()/
// recovery_delete_character() directly, via the DEBUG_LINK-only
// recovery_debugLinkStart() hook that arms a ceremony without going through
// recovery_cipher_init()'s confirm()/PIN gate (which blocks on a real button
// press and cannot run headless here).
// unittests/firmware/test_board.cpp -- single guarded board bootstrap for
// the whole binary; see that file for why this must never be called
// directly outside it.
void kk_test_board_init(void);

namespace {

class RecoveryCipher : public ::testing::Test {
 protected:
  void SetUp() override {
    kk_test_board_init();  // canvas for next_character()'s layout_cipher() draw
    static bool fsm_ready = false;
    if (!fsm_ready) {
      fsm_init();
      fsm_ready = true;
    }
    setup_abort();
  }

  void TearDown() override { setup_abort(); }
};

// Looks up the raw cipher byte that currently decodes to `plain`.
char CipherCharFor(char plain) { return recovery_get_cipher()[plain - 'a']; }

// Types `word` (at most 4 chars -- recovery_character() rejects a longer
// in-progress word) through the ACTIVE cipher, one character at a time, so
// each byte sent is the raw cipher-encoded form of a real plaintext letter.
void TypeViaCipher(const char *word) {
  for (const char *p = word; *p; ++p) {
    char buf[2] = {CipherCharFor(*p), '\0'};
    recovery_character(buf);
  }
}

// Types `word` verbatim, unencoded -- simulating a host bypassing the
// substitution cipher and sending real letters directly.
void TypeRaw(const char *word) {
  for (const char *p = word; *p; ++p) {
    char buf[2] = {*p, '\0'};
    recovery_character(buf);
  }
}

void TypeSpace() { recovery_character(" "); }

void Backspace(int n) {
  for (int i = 0; i < n; ++i) recovery_delete_character();
}

}  // namespace

TEST_F(RecoveryCipher, BackspaceWithinWord) {
  recovery_debugLinkStart(/*word_count=*/0);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  TypeViaCipher("aban");
  EXPECT_STREQ(recovery_get_decoded_mnemonic(), "aban");

  Backspace(1);
  EXPECT_STREQ(recovery_get_decoded_mnemonic(), "aba");

  TypeViaCipher("n");
  EXPECT_STREQ(recovery_get_decoded_mnemonic(), "aban");
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
}

TEST_F(RecoveryCipher, BackspaceAcrossOneWordBoundaryRestoresRawBytes) {
  recovery_debugLinkStart(/*word_count=*/0);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  std::string word1_raw;
  for (const char *p = "aban"; *p; ++p) {
    char c = CipherCharFor(*p);
    word1_raw += c;
    char buf[2] = {c, '\0'};
    recovery_character(buf);
  }
  TypeSpace();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  ASSERT_STREQ(recovery_get_decoded_mnemonic(), "aban ");

  Backspace(1);  // delete the trailing space

  EXPECT_STREQ(recovery_get_decoded_mnemonic(), "aban");
}

// The exact repro from #584: complete two words, then back up across BOTH
// of them (deleting word2 entirely and the space in front of it), landing
// back in the middle of editing word1. coded_mnemonic must hold word1's own
// raw bytes, not word2's -- which is precisely what the single-slot
// last_completed_coded_word fix in PR #582 got wrong.
TEST_F(RecoveryCipher, BackspaceAcrossTwoWordBoundariesRestoresRawBytes) {
  recovery_debugLinkStart(/*word_count=*/0);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  std::string word1_raw;
  for (const char *p = "aban"; *p; ++p) {
    char c = CipherCharFor(*p);
    word1_raw += c;
    char buf[2] = {c, '\0'};
    recovery_character(buf);
  }
  TypeSpace();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  TypeViaCipher("abil");  // "ability"
  TypeSpace();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  ASSERT_STREQ(recovery_get_decoded_mnemonic(), "aban abil ");

  // trailing space, all 4 letters of word2, and the space before it: 6 deletes.
  Backspace(6);

  EXPECT_STREQ(recovery_get_decoded_mnemonic(), "aban")
      << "plaintext should be back to word1 alone";
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
}

// Generalizes the above to 24 words and 23 boundaries. BIP39's wordlist
// guarantees every word's first four letters are a globally unique prefix,
// so wordlist[i]'s first four characters are always a valid, unambiguous
// word to type here.
TEST_F(RecoveryCipher, BackspaceAcross23WordBoundariesRestoresRawBytes) {
  recovery_debugLinkStart(/*word_count=*/0);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  std::string word1_raw;
  for (const char *p = wordlist[0]; p < wordlist[0] + 4; ++p) {
    char c = CipherCharFor(*p);
    word1_raw += c;
    char buf[2] = {c, '\0'};
    recovery_character(buf);
  }
  TypeSpace();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  // Complete words at indices 1..22 (22 more words: 23 completed words and
  // 23 boundaries total, counting word0). recovery_cipher.c enforces a
  // 24-word ceremony maximum (words_entered > 24 aborts), so the 24th word
  // (index 23) is typed but deliberately left un-space-completed below --
  // completing it would step words_entered to 25, one past the legitimate
  // maximum, for a reason unrelated to what this test is checking.
  int deletes = 1;  // the space just typed after word1
  for (int w = 1; w < 23; w++) {
    char prefix[5] = {0};
    memcpy(prefix, wordlist[w], 4);
    TypeViaCipher(prefix);
    TypeSpace();
    ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY)) << "word index " << w;
    // Not every BIP39 word has 4+ letters (e.g. "act"), so count what was
    // actually typed rather than assuming 4 letters + a space every time.
    deletes += static_cast<int>(strlen(prefix)) + 1;
  }

  char last_prefix[5] = {0};
  memcpy(last_prefix, wordlist[23], 4);
  TypeViaCipher(last_prefix);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  deletes += static_cast<int>(strlen(last_prefix));

  Backspace(deletes);

  EXPECT_STREQ(recovery_get_decoded_mnemonic(),
               std::string(wordlist[0], 4).c_str());
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
}

// Interleave typing, deleting, and retyping a correction, checking after
// every step that the plaintext mnemonic, the raw coded history, and the
// word count implied by them stay mutually consistent.
TEST_F(RecoveryCipher, RepeatedDeleteRetypeStaysAligned) {
  recovery_debugLinkStart(/*word_count=*/0);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  TypeViaCipher("aban");
  TypeSpace();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  ASSERT_STREQ(recovery_get_decoded_mnemonic(), "aban ");

  TypeViaCipher("abou");  // start typing a wrong word ("about")
  ASSERT_STREQ(recovery_get_decoded_mnemonic(), "aban abou");

  Backspace(4);  // realize the mistake, delete all four letters
  ASSERT_STREQ(recovery_get_decoded_mnemonic(), "aban ");

  TypeViaCipher("abov");  // correct to "above" instead
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_STREQ(recovery_get_decoded_mnemonic(), "aban abov");

  TypeSpace();
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_STREQ(recovery_get_decoded_mnemonic(), "aban abov ");
}

// After a multi-boundary backspace, a host sending a real BIP39 prefix
// directly (bypassing the cipher entirely) must still be caught -- proving
// coded_word/coded_mnemonic aren't left holding stale bytes from an earlier,
// already-backed-out-of word that would mask the raw prefix.
TEST_F(RecoveryCipher, RawPrefixAfterMultiBoundaryBackspaceStillCaught) {
  recovery_debugLinkStart(/*word_count=*/0);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  TypeViaCipher("aban");
  TypeSpace();
  TypeViaCipher("abil");
  TypeSpace();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  Backspace(
      6);  // back into the middle of word1, same as the boundary test above
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  ASSERT_STREQ(recovery_get_decoded_mnemonic(), "aban");

  Backspace(4);  // and all the way out, so the next word starts clean
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  ASSERT_STREQ(recovery_get_decoded_mnemonic(), "");

  // Try a few fixed real-word prefixes raw and take whichever one's
  // cipher-decoded form ISN'T itself coincidentally a valid prefix too (the
  // production code's own comment documents a ~0.4% coincidence rate for
  // any single one -- trying several fixed candidates makes the test
  // deterministic regardless of this ceremony's randomly generated cipher).
  static const char *kCandidates[] = {"aban", "abil", "able", "abou", "abov"};
  bool caught = false;
  for (const char *candidate : kCandidates) {
    char decoded_probe[8] = {0};
    for (size_t i = 0; i < strlen(candidate); i++) {
      const char *pos = strchr(recovery_get_cipher(), candidate[i]);
      ASSERT_NE(pos, nullptr);
      decoded_probe[i] =
          "abcdefghijklmnopqrstuvwxyz"[pos - recovery_get_cipher()];
    }
    if (attempt_auto_complete(decoded_probe)) {
      continue;  // this candidate's raw form also happens to decode validly
    }

    TypeRaw(candidate);
    if (!setup_isArmedAs(SETUP_RECOVERY)) {
      caught = true;  // mid-word uncyphered-count check aborted it
      break;
    }
    TypeSpace();
    if (!setup_isArmedAs(SETUP_RECOVERY)) {
      caught = true;  // space-completion wordlist validation aborted it
      break;
    }
    // Accepted outright: re-arm and try the next candidate. setup_abort()
    // first -- setup_stage() (inside recovery_debugLinkStart()) refuses to
    // restage over an already-armed ceremony.
    setup_abort();
    recovery_debugLinkStart(/*word_count=*/0);
  }

  EXPECT_TRUE(caught) << "a raw, unenciphered real-word prefix must be "
                         "rejected, not silently accepted as if the cipher "
                         "had been used";
}

/* A cipher-recovery ceremony driven entirely with separators: words_entered
 * counts separators, but strtok() collapses runs of them, so the count gate
 * passes while the phrase that reaches the commit has no words in it at all.
 * Committing that stores the empty mnemonic, whose seed is public. */
TEST(Recovery, SpacesOnlyCeremonyIsRefusedAndCommitsNothing) {
  // preload also performs the one-per-binary board bootstrap, fsm_init() and
  // usbInit(); one decision answers recovery_cipher_init()'s confirm screen.
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ensure_recovery_storage_ready();
  storage_wipe();
  // Wiping flash does not reset the RAM shadow. A reused emulator image or
  // preceding wallet test can leave it initialized; match WipeDevice's order.
  storage_reset();
  ASSERT_FALSE(storage_isInitialized());

  // enforce_wordlist is omitted by default on the wire. Firmware now ignores
  // it and always checks words, but the empty ceremony must still be refused
  // by the word-count guard before any check runs.
  recovery_cipher_init(/*word_count=*/12, /*passphrase_protection=*/false,
                       /*pin_protection=*/false, "english", "spaces",
                       /*enforce_wordlist=*/false, /*auto_lock_delay_ms=*/0,
                       /*u2f_counter=*/0, /*dry_run=*/false);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  for (int i = 0; i < 12; i++) {
    recovery_character(" ");
  }

  EXPECT_FALSE(storage_isInitialized())
      << "a ceremony that produced no words must not commit a seed";
  EXPECT_FALSE(setup_isArmed());
  (void)kkconfirm_drain();
  storage_wipe();
  storage_reset();
  layoutHomeForced();
}

// The recovery call site: with a failed RNG verdict the cipher shuffle must
// refuse and disarm the ceremony instead of showing a predictable cipher. The
// old unchecked shuffle left it armed. Control: a healthy verdict arms it.
TEST(Recovery, FailedRngVerdictRefusesTheCipherAndDisarms) {
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ensure_recovery_storage_ready();
  storage_wipe();
  storage_reset();

  recovery_review_reset_cipher_draws();
  rng_health_force_verdict(false);
  recovery_cipher_init(/*word_count=*/12, /*passphrase_protection=*/false,
                       /*pin_protection=*/false, "english", "spaces",
                       /*enforce_wordlist=*/false, /*auto_lock_delay_ms=*/0,
                       /*u2f_counter=*/0, /*dry_run=*/false);
  rng_health_force_verdict(true);
  EXPECT_FALSE(setup_isArmed())
      << "a failed RNG verdict must not leave a recovery ceremony armed";
  EXPECT_EQ(0u, recovery_review_cipher_draws())
      << "the cipher must never be rendered, even briefly before aborting";
  (void)kkconfirm_drain();

  ASSERT_TRUE(kkconfirm_preload(1, 0));
  recovery_cipher_init(/*word_count=*/12, /*passphrase_protection=*/false,
                       /*pin_protection=*/false, "english", "spaces",
                       /*enforce_wordlist=*/false, /*auto_lock_delay_ms=*/0,
                       /*u2f_counter=*/0, /*dry_run=*/false);
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY)) << "control: healthy RNG arms";
  EXPECT_EQ(1u, recovery_review_cipher_draws())
      << "control: the observer must see the healthy recovery screen";
  recovery_cipher_abort();
  (void)kkconfirm_drain();
  storage_wipe();
  storage_reset();
  layoutHomeForced();
}

TEST(Recovery, UnrelatedTransportFailureKeepsCurrentCipherVisible) {
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ensure_recovery_storage_ready();
  setup_abort();
  recovery_cipher_init(/*word_count=*/12, /*passphrase_protection=*/false,
                       /*pin_protection=*/false, "english", "recovery",
                       /*enforce_wordlist=*/true, /*auto_lock_delay_ms=*/0,
                       /*u2f_counter=*/0, /*dry_run=*/false);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  ASSERT_EQ(AWAY_FROM_HOME, home_get_state());
  const Canvas* canvas = layout_get_canvas();
  ASSERT_NE(nullptr, canvas);
  for (int frame = 0; frame < 20; ++frame) {
    force_animation_start();
    animate();
  }
  const size_t bytes = canvas->width * canvas->height;
  bool cipher_drawn = false;
  for (size_t y = 0; y < canvas->height; ++y) {
    for (size_t x = CIPHER_START_X; x < canvas->width; ++x) {
      cipher_drawn |= canvas->buffer[y * canvas->width + x] != 0;
    }
  }
  ASSERT_TRUE(cipher_drawn)
      << "test must capture a rendered cipher, not a blank queue";
  std::vector<uint8_t> cipher_before(canvas->buffer, canvas->buffer + bytes);

  /* A previously active signer also calls layoutHome() while it aborts. The
   * recovery redraw must restore the cipher after that cleanup. */
  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  call_msg_failure_handler(FailureType_Failure_UnexpectedMessage,
                           "Unknown message");
  for (int frame = 0; frame < 20; ++frame) {
    force_animation_start();
    animate();
  }
  EXPECT_FALSE(signing_is_active());
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_EQ(AWAY_FROM_HOME, home_get_state());
  EXPECT_EQ(cipher_before,
            std::vector<uint8_t>(canvas->buffer, canvas->buffer + bytes))
      << "the same substitution cipher must remain visible for the next word";

  setup_abort();
  (void)kkconfirm_drain();
  layoutHomeForced();
}

// GetCoinTable passes the dispatch gate during a ceremony. A malformed one is
// refused without drawing home over the cipher, and recovery stays armed.
TEST(Recovery, MalformedGetCoinTableKeepsTheCipher) {
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ensure_recovery_storage_ready();
  setup_abort();
  recovery_cipher_init(/*word_count=*/12, /*passphrase_protection=*/false,
                       /*pin_protection=*/false, "english", "recovery",
                       /*enforce_wordlist=*/true, /*auto_lock_delay_ms=*/0,
                       /*u2f_counter=*/0, /*dry_run=*/false);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  const Canvas* canvas = layout_get_canvas();
  ASSERT_NE(nullptr, canvas);
  for (int frame = 0; frame < 20; ++frame) {
    force_animation_start();
    animate();
  }
  const size_t bytes = canvas->width * canvas->height;
  bool cipher_drawn = false;
  for (size_t y = 0; y < canvas->height; ++y) {
    for (size_t x = CIPHER_START_X; x < canvas->width; ++x) {
      cipher_drawn |= canvas->buffer[y * canvas->width + x] != 0;
    }
  }
  ASSERT_TRUE(cipher_drawn);
  std::vector<uint8_t> cipher_before(canvas->buffer, canvas->buffer + bytes);

  GetCoinTable unpaired = {};  // start without end
  unpaired.has_start = true;
  GetCoinTable out_of_range = {};
  out_of_range.has_start = true;
  out_of_range.has_end = true;
  out_of_range.start = 0xffffffff;
  out_of_range.end = 0xffffffff;
  for (GetCoinTable* bad : {&unpaired, &out_of_range}) {
    ASSERT_TRUE(
        keepkey_before_message_dispatch(MessageType_MessageType_GetCoinTable));
    fsm_test_clearLastFailure();
    fsm_msgGetCoinTable(bad);
    for (int frame = 0; frame < 20; ++frame) {
      force_animation_start();
      animate();
    }
    EXPECT_EQ(FailureType_Failure_Other, fsm_test_lastFailureCode());
    EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
    EXPECT_EQ(AWAY_FROM_HOME, home_get_state());
    EXPECT_EQ(cipher_before,
              std::vector<uint8_t>(canvas->buffer, canvas->buffer + bytes))
        << "a malformed GetCoinTable drew over the recovery cipher";
  }

  setup_abort();
  (void)kkconfirm_drain();
  layoutHomeForced();
}

// The same over an armed reset: whatever the ceremony left on screen stays.
TEST(Recovery, MalformedGetCoinTableKeepsAnArmedResetScreen) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ensure_recovery_storage_ready();
  setup_abort();
  ASSERT_TRUE(setup_stage(false, "english", "reset", 0, 0, false));
  setup_arm(SETUP_RESET);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  layout_simple_message("Reset armed");
  const Canvas* canvas = layout_get_canvas();
  ASSERT_NE(nullptr, canvas);
  for (int frame = 0; frame < 20; ++frame) {
    force_animation_start();
    animate();
  }
  ASSERT_EQ(AWAY_FROM_HOME, home_get_state());
  const size_t bytes = canvas->width * canvas->height;
  std::vector<uint8_t> screen_before(canvas->buffer, canvas->buffer + bytes);

  GetCoinTable unpaired = {};
  unpaired.has_start = true;
  ASSERT_TRUE(
      keepkey_before_message_dispatch(MessageType_MessageType_GetCoinTable));
  fsm_test_clearLastFailure();
  fsm_msgGetCoinTable(&unpaired);
  for (int frame = 0; frame < 20; ++frame) {
    force_animation_start();
    animate();
  }
  EXPECT_EQ(FailureType_Failure_Other, fsm_test_lastFailureCode());
  EXPECT_TRUE(setup_isArmedAs(SETUP_RESET));
  EXPECT_EQ(AWAY_FROM_HOME, home_get_state());
  EXPECT_EQ(screen_before,
            std::vector<uint8_t>(canvas->buffer, canvas->buffer + bytes))
      << "a malformed GetCoinTable drew home over an armed reset";

  setup_abort();
  (void)kkconfirm_drain();
  layoutHomeForced();
}

// A plain Ping or a second ceremony start during recovery is answered without
// hiding the cipher, and a signing request ends the ceremony instead of
// running beside it.
TEST(Recovery, UnrelatedRequestsKeepTheCipherAndSigningEndsTheCeremony) {
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ensure_recovery_storage_ready();
  setup_abort();
  recovery_cipher_init(/*word_count=*/12, /*passphrase_protection=*/false,
                       /*pin_protection=*/false, "english", "recovery",
                       /*enforce_wordlist=*/true, /*auto_lock_delay_ms=*/0,
                       /*u2f_counter=*/0, /*dry_run=*/false);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  const Canvas* canvas = layout_get_canvas();
  ASSERT_NE(nullptr, canvas);
  for (int frame = 0; frame < 20; ++frame) {
    force_animation_start();
    animate();
  }
  const size_t bytes = canvas->width * canvas->height;
  std::vector<uint8_t> cipher_before(canvas->buffer, canvas->buffer + bytes);

  Ping ping = {};
  fsm_msgPing(&ping);
  for (int frame = 0; frame < 20; ++frame) {
    force_animation_start();
    animate();
  }
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_EQ(cipher_before,
            std::vector<uint8_t>(canvas->buffer, canvas->buffer + bytes))
      << "Ping must not draw home over the recovery cipher";

  // A second ceremony start is refused without hiding the armed one.
  RecoveryDevice again = {};
  fsm_msgRecoveryDevice(&again);
  for (int frame = 0; frame < 20; ++frame) {
    force_animation_start();
    animate();
  }
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_EQ(cipher_before,
            std::vector<uint8_t>(canvas->buffer, canvas->buffer + bytes))
      << "a refused RecoveryDevice must not draw home over the cipher";

  // Requests that would draw over the ceremony are refused untouched.
  EXPECT_FALSE(
      keepkey_before_message_dispatch(MessageType_MessageType_GetAddress));
  EXPECT_FALSE(
      keepkey_before_message_dispatch(MessageType_MessageType_GetPublicKey));
  Ping protected_ping = {};
  protected_ping.has_button_protection = true;
  protected_ping.button_protection = true;
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  fsm_msgPing(&protected_ping);
  EXPECT_EQ(0, kkconfirm_drain()) << "no prompt may be drawn mid-ceremony";
  // An authenticator Ping is PIN-gated: refused, never served.
  Ping auth_ping = {};
  auth_ping.has_message = true;
  std::strcpy(auth_ping.message, "\x17getAccount:0");
  kkconfirm_sendTiny(MessageType_MessageType_Cancel, nullptr, 0);
  fsm_test_clearLastFailure();
  fsm_msgPing(&auth_ping);
  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode())
      << "an authenticator Ping was handled mid-ceremony";
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  (void)kkconfirm_drain();
  for (int frame = 0; frame < 20; ++frame) {
    force_animation_start();
    animate();
  }
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_EQ(cipher_before,
            std::vector<uint8_t>(canvas->buffer, canvas->buffer + bytes))
      << "a refused request must leave the cipher on screen";
  // Requests that end the ceremony still reach their handlers.
  EXPECT_TRUE(
      keepkey_before_message_dispatch(MessageType_MessageType_Initialize));

#if !BITCOIN_ONLY
  EXPECT_TRUE(
      keepkey_before_message_dispatch(MessageType_MessageType_EthereumSignTx));
  EXPECT_FALSE(setup_isArmed())
      << "a signing request must end the ceremony, not run beside it";
#endif

  setup_abort();
  (void)kkconfirm_drain();
  layoutHomeForced();
}

extern "C" {
void recovery_review_seed_scratch(void);
bool recovery_review_scratch_empty(void);
void setup_abort(void);
void recovery_cipher_reset(void);
bool recovery_review_delete_resync(const char*, const char*, bool, char*,
                                   char*);
}

TEST(Recovery, DeleteKeepsTypedCipherCharactersNotTheCurrentMapping) {
  char coded[12], decoded[12];
  // "ab" remains of word "abc", typed as "qwe" under per-character ciphers.
  EXPECT_FALSE(
      recovery_review_delete_resync("zoo ab", "qwe", false, coded, decoded));
  EXPECT_STREQ("qw", coded);  // recomputing from the identity would be "ab"
  EXPECT_STREQ("ab", decoded);

  // Stepping back over a space into a finished word: its typed characters
  // were discarded, so the heuristic must not see a guessed coded prefix.
  EXPECT_TRUE(recovery_review_delete_resync("zoo", "", false, coded, decoded));
  EXPECT_STREQ("", coded);
  EXPECT_STREQ("zoo", decoded);

  // Once unknown, stays unknown until the word is emptied.
  EXPECT_TRUE(recovery_review_delete_resync("zo", "x", true, coded, decoded));
  EXPECT_STREQ("", coded);
  EXPECT_FALSE(recovery_review_delete_resync("", "", true, coded, decoded));
  EXPECT_STREQ("", decoded);
}
TEST(Recovery, AbortAndResetClearPreviousWordAndDisplayEquivalent) {
  recovery_review_seed_scratch();
  ASSERT_FALSE(recovery_review_scratch_empty());
  setup_abort();
  EXPECT_TRUE(recovery_review_scratch_empty());
  recovery_review_seed_scratch();
  recovery_cipher_reset();
  EXPECT_TRUE(recovery_review_scratch_empty());
  setup_abort();
  EXPECT_TRUE(recovery_review_scratch_empty());
}

// The previous-word indicator must stay on one line: a wrapped second line
// lands on "Recovery Cipher:".
TEST(Recovery, PrevWordIndicatorFitsOneLine) {
  const Font* font = get_body_font();
  char info[32];
  int overflows = 0;
  for (uint32_t pos = 1; pos <= 24; pos++) {
    for (int i = 0; wordlist[i]; i++) {
      recovery_cipher_prev_word_info(info, sizeof(info), pos, wordlist[i]);
      uint32_t width = calc_str_width(font, info);
      if (width > CIPHER_PREV_WORD_WIDTH) {
        if (overflows++ < 5) ADD_FAILURE() << info << " is " << width << " px";
      }
    }
  }
  EXPECT_EQ(0, overflows);
}
