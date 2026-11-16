/* Interrupt within begin and export_one, while the handler retains s. */
#include "monero_session_probe.h"
#include "keepkey/rand/rng_health.h"
static bool interrupt_random(uint8_t* out, size_t size) {
  if (monero_session_interrupt) monero_session_interrupt();
  return random_buffer_checked(out, size);
}
#define random_buffer_checked interrupt_random
#define monero_session_expire probe_monero_session_expire
#define monero_session_abort probe_monero_session_abort
#define monero_key_image_active probe_monero_key_image_active
#define monero_key_image_begin probe_monero_key_image_begin
#define monero_key_image_step probe_monero_key_image_step
#define monero_key_image_finish probe_monero_key_image_finish
#include "../../lib/firmware/monero_key_image.c"
