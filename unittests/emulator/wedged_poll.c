/* Standalone native regression: include the implementation to inject the
 * post-timeout state without adding a production FFI that can force a wedge.
 * Link against the normal native firmware libraries; no initialized wallet
 * or live firmware thread is needed to test these public API boundaries. */
#include "../../lib/emulator/libkkemu.c"
#undef NDEBUG /* This executable must check its assertions in release builds. \
               */
#include <assert.h>

int main(void) {
  static uint8_t flash[KKEMU_FLASH_SIZE];
  memset(flash, 0xFF, sizeof(flash));
  assert(kkemu_init(flash, sizeof(flash)) == 0);

  /* A clean thread-driven stop may inject Cancel after the poll loop has
   * already observed POLL_SET(0). The stop contract must remove that wakeup
   * before a later start, or the next confirmation consumes stale input. */
  assert(kkemu_start() == 0);
  kkemu_sleep_ms(KKEMU_POLL_INTERVAL_MS * 2);
  kkemu_stop();
  assert(!POLL_RUNNING());
  assert(ringbuf_empty(&rb_main_in));

  /* Prove the same initialized emulator can start and stop again with a clean
   * input boundary. Removing the post-join ring reset makes one of these
   * assertions observe the synthetic Cancel. */
  assert(kkemu_start() == 0);
  kkemu_sleep_ms(KKEMU_POLL_INTERVAL_MS * 2);
  kkemu_stop();
  assert(!POLL_RUNNING());
  assert(ringbuf_empty(&rb_main_in));

  libkkemu_initialized = 1;
  g_poll_wedged = 1;
  POLL_SET(0);

  /* No snapshot or second firmware execution after a timed-out stop. */
  assert(kkemu_trylock() == 0);
  assert(kkemu_poll() == -1);
  assert(kkemu_start() == -1);
  int width = 256, height = 64;
  assert(kkemu_get_display(&width, &height) == NULL);
  assert(width == 0 && height == 0);

#ifndef _WIN32
  /* Legacy blocking callers must still hold the actual mutex. */
  kkemu_lock();
  assert(pthread_mutex_trylock(&g_fw_lock) != 0);
  kkemu_unlock();
  assert(pthread_mutex_trylock(&g_fw_lock) == 0);
  pthread_mutex_unlock(&g_fw_lock);
#endif
  return 0;
}
