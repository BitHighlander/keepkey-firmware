/* Test-only xmr_crypto_rng32(). Defining it here keeps the archive member
 * lib/firmware/monero/crypto_rng.c out of this link; see that file. */
#include "monero_test_rng.h"

#include <stdbool.h>
#include <string.h>

#include "keepkey/firmware/monero/crypto.h"
#include "trezor/crypto/sha3.h"

#ifndef XMR_TEST_RNG_NO_CHECKED
#include "keepkey/rand/rng_health.h"
#endif

typedef enum { MODE_CHECKED, MODE_REPLAY, MODE_FAIL } rng_mode;

static rng_mode mode = MODE_CHECKED;
static uint8_t replay_seed[32];
static uint32_t draws;
void (*xmr_test_rng_interrupt)(void);

void xmr_test_rng_checked(void) {
  mode = MODE_CHECKED;
  draws = 0;
}

void xmr_test_rng_replay(const uint8_t seed[32]) {
  mode = MODE_REPLAY;
  memcpy(replay_seed, seed, 32);
  draws = 0;
}

void xmr_test_rng_fail(void) {
  mode = MODE_FAIL;
  draws = 0;
}

uint32_t xmr_test_rng_draws(void) { return draws; }

void xmr_test_stream(uint8_t out[32], const char *label,
                     const uint8_t seed[32], uint32_t ctr) {
  uint8_t c[4] = {(uint8_t)ctr, (uint8_t)(ctr >> 8), (uint8_t)(ctr >> 16),
                  (uint8_t)(ctr >> 24)};
  SHA3_CTX k;
  keccak_256_Init(&k);
  keccak_Update(&k, (const uint8_t *)label, strlen(label));
  keccak_Update(&k, seed, 32);
  keccak_Update(&k, c, sizeof(c));
  keccak_Final(&k, out);
}

bool xmr_crypto_rng32(uint8_t out[32]) {
  uint32_t k = draws++;
  if (xmr_test_rng_interrupt) {
    void (*hook)(void) = xmr_test_rng_interrupt;
    xmr_test_rng_interrupt = 0;
    hook();
  }
  switch (mode) {
    case MODE_REPLAY:
      xmr_test_stream(out, "KKXMR-test-rng-v1", replay_seed, k);
      return true;
    case MODE_FAIL:
      memset(out, 0, 32);
      return false;
    case MODE_CHECKED:
    default:
#ifndef XMR_TEST_RNG_NO_CHECKED
      return random_buffer_checked(out, 32);
#else
      memset(out, 0, 32);
      return false;
#endif
  }
}
