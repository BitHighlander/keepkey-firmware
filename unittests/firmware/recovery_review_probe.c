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
