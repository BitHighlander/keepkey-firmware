/* Compile the real implementation into firmware-unit to inspect live scratch;
 * production has neither a secret getter nor test mutation hooks. */
#include "../../lib/firmware/recovery_cipher.c"

bool recovery_review_scratch_empty(void) {
  const unsigned char* buffers[] = {(const unsigned char*)last_completed_word,
                                    (const unsigned char*)prev_info};
  const size_t sizes[] = {sizeof(last_completed_word), sizeof(prev_info)};
  for (size_t b = 0; b < 2; ++b)
    for (size_t i = 0; i < sizes[b]; ++i)
      if (buffers[b][i]) return false;
  return true;
}

void recovery_review_seed_scratch(void) {
  strcpy(last_completed_word, "abandon");
  strcpy(prev_info, "(1.abandon)");
}

/* Delete resync with a controlled mnemonic (already edited) and the coded
 * characters the user really typed. The cipher is set to the identity, so a
 * resync that recomputed coded characters from it would visibly differ. */
bool recovery_review_delete_resync(const char* mnemonic_after_delete,
                                   const char* typed, bool unknown,
                                   char coded_out[12], char decoded_out[12]) {
  strlcpy(mnemonic, mnemonic_after_delete, sizeof(mnemonic));
  strlcpy(coded_word, typed, sizeof(coded_word));
  strlcpy(cipher, english_alphabet, sizeof(cipher));
  coded_word_unknown = unknown;
  resync_current_word_after_delete();
  memcpy(coded_out, coded_word, sizeof(coded_word));
  memcpy(decoded_out, decoded_word, sizeof(decoded_word));
  const bool result = coded_word_unknown;
  recovery_cipher_reset();
  return result;
}
