extern "C" {
#include "keepkey/firmware/recovery_cipher.h"
#include "trezor/crypto/bip39_english.h"
}

#include "gtest/gtest.h"

#include <cstring>

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
  EXPECT_FALSE(recovery_review_delete_resync("zoo ab", "qwe", false, coded,
                                             decoded));
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
