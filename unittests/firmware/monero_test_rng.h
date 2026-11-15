/* Test-only replacement for xmr_crypto_rng32() (lib/firmware/monero/
 * crypto_rng.c). Linked into firmware-unit and the vector generator only;
 * firmware and the emulator never contain it. */
#ifndef MONERO_TEST_RNG_H
#define MONERO_TEST_RNG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Default: every draw goes to random_buffer_checked(), as in firmware. */
void xmr_test_rng_checked(void);
/* Replay draw k as Keccak256("KKXMR-test-rng-v1" || seed || le32 k). */
void xmr_test_rng_replay(const uint8_t seed[32]);
/* Every draw fails (returns false with the buffer zeroed). */
void xmr_test_rng_fail(void);
/* Draws made since the last mode change. */
uint32_t xmr_test_rng_draws(void);

/* Keccak256(label || seed || le32 ctr): the deterministic stream used for
 * replayed draws and for the generator's synthetic inputs. */
void xmr_test_stream(uint8_t out[32], const char *label,
                     const uint8_t seed[32], uint32_t ctr);

#ifdef __cplusplus
}
#endif

#endif
