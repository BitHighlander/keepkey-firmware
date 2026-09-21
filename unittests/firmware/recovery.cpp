extern "C" {
#include "keepkey/board/layout.h"
#include "keepkey/emulator/setup.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/recovery_cipher.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/storage.h"
#include "trezor/crypto/bip39_english.h"
}

#include "gtest/gtest.h"

#include <cstring>

bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

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

/* A cipher-recovery ceremony driven entirely with separators: words_entered
 * counts separators, but strtok() collapses runs of them, so the count gate
 * passes while the phrase that reaches the commit has no words in it at all.
 * Committing that stores the empty mnemonic, whose seed is public. */
TEST(Recovery, SpacesOnlyCeremonyIsRefusedAndCommitsNothing) {
  // preload also performs the one-per-binary board bootstrap, fsm_init() and
  // usbInit(); one decision answers recovery_cipher_init()'s confirm screen.
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  static bool storage_ready = false;
  if (!storage_ready) {
    setup();  // urandom + the emulator's mmap'd flash, as storage needs
    storage_init();
    storage_ready = true;
  }
  storage_wipe();
  ASSERT_FALSE(storage_isInitialized());

  // enforce_wordlist is omitted by default on the wire, which is what makes
  // the commit condition skip mnemonic_check() entirely.
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
  layoutHomeForced();
}
