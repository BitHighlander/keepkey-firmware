/*
 * libkkemu — KeepKey firmware emulator as a shared library.
 *
 * Replaces main() with kkemu_init/poll/shutdown. Uses ring buffers
 * instead of UDP sockets for message I/O.
 */
#include "keepkey/emulator/libkkemu.h"
#include "keepkey/emulator/emulator.h"
#include "keepkey/emulator/setup.h"
#include "keepkey/board/canvas.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/timer.h"
#if DEBUG_LINK && !BITCOIN_ONLY
#include "keepkey/firmware/clearsign_root.h"
#endif
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/rand/rng.h"
#include "ringbuf.h"
#include "trezor/crypto/memzero.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN /* exclude winsock.h — it declares \
                               shutdown(SOCKET,int) */
#include <windows.h>
#else
#include <sys/mman.h>
#include <pthread.h>
#include <time.h>
#endif

/* Defined in firmware — we just need the declaration */
extern void fsm_init(void);

/* ── Poll thread (Approach B: reactive confirm) ──────────────────────────
 *
 * Optional: the host calls kkemu_start() to run the firmware event loop on a
 * dedicated thread inside the dylib. This lets confirm_helper's blocking C
 * busy-loop wait for a button decision IN C without freezing the host's event
 * loop — so the vault can render the real OLED confirm frame, HOLD it, and
 * deliver the DebugLinkDecision only when the user clicks (screen-first gating,
 * like a physical device).
 *
 * Only the poll thread ever drives firmware execution (kkemu_poll_body). The
 * host interacts solely through the lock-free SPSC rings (kkemu_write/read,
 * kkemu_pop_frame). g_fw_lock serializes the poll body against host-side flash
 * snapshots (kkemu_lock/unlock) so storage_commit can't tear a saveFlash read.
 *
 * When the thread is NOT started (g_poll_running == 0) the dylib stays purely
 * single-threaded and host-driven via kkemu_poll() — exactly as the FFI test
 * suite and python-keepkey tests use it. The lock helpers no-op in that mode.
 */
#ifdef _WIN32
static CRITICAL_SECTION g_fw_lock;
static int g_fw_lock_ready = 0; /* initialized once, never deleted */
static HANDLE g_poll_thread = NULL;
#define FW_LOCK() EnterCriticalSection(&g_fw_lock)
#define FW_UNLOCK() LeaveCriticalSection(&g_fw_lock)
#define FW_TRYLOCK() TryEnterCriticalSection(&g_fw_lock)
#else
static pthread_mutex_t g_fw_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_poll_thread;
#define FW_LOCK() pthread_mutex_lock(&g_fw_lock)
#define FW_UNLOCK() pthread_mutex_unlock(&g_fw_lock)
#define FW_TRYLOCK() (pthread_mutex_trylock(&g_fw_lock) == 0)
#endif

/* Cross-thread poll-running flag. _Atomic (not volatile — volatile is not a
 * synchronization primitive in C): the poll thread reads it each loop while
 * start/stop write it from the host thread. acquire/release publishes the
 * surrounding firmware/ring state alongside the flag. */
#include <stdatomic.h>
static _Atomic int g_poll_running = 0;
/* A stop request is not proof that the thread has exited. Keep ownership of
 * firmware and host flash until it has actually been joined. Lifecycle calls
 * are serialized by the host; ring consumers may run concurrently. */
static _Atomic int g_poll_joinable = 0;
static _Atomic int g_poll_exited = 0;
static int g_stop_cancel_injected = 0;
#define POLL_RUNNING() \
  atomic_load_explicit(&g_poll_running, memory_order_acquire)
#define POLL_SET(v) \
  atomic_store_explicit(&g_poll_running, (v), memory_order_release)

/* This host thread owns g_fw_lock; unlock keys on this, not on
 * g_poll_running. Per thread, so a thread that got the no-poll-thread success
 * from kkemu_trylock() cannot release a lock another thread still holds. */
#ifdef _WIN32
/* Not _Thread_local on Windows: MinGW emulates thread-locals through the
 * shared libgcc, so the DLL would import libgcc_s_seh-1.dll, which Windows
 * does not ship. The owner's thread id says the same thing. It is written
 * only while g_fw_lock is held, and a thread id is never 0. */
static _Atomic DWORD g_host_lock_owner = 0;
#define HOST_HOLDS_LOCK() \
  (atomic_load(&g_host_lock_owner) == GetCurrentThreadId())
#define HOST_HOLDS_SET(v) \
  atomic_store(&g_host_lock_owner, (v) ? GetCurrentThreadId() : 0)
#else
static _Thread_local int g_host_holds_lock = 0;
#define HOST_HOLDS_LOCK() g_host_holds_lock
#define HOST_HOLDS_SET(v) (g_host_holds_lock = (v))
#endif

/* ── Ring buffers (replace UDP sockets) ─────────────────────────────── */

static RingBuf rb_main_in;   /* host → firmware (main interface) */
static RingBuf rb_main_out;  /* firmware → host (main interface) */
static RingBuf rb_debug_in;  /* host → firmware (debug link) */
static RingBuf rb_debug_out; /* firmware → host (debug link) */

static int libkkemu_initialized = 0;

/* ── Display capture ring ───────────────────────────────────────────── */

/*
 * Captures every display_refresh() into a ring of 1-bit packed snapshots.
 * The host drains via kkemu_pop_frame(). Adjacent identical frames are
 * skipped so an idle firmware doesn't spam the ring.
 *
 * Sized for ~4 seconds at 16ms refresh. Cross-thread in thread-driven mode:
 * the poll thread is the sole producer, the host (kkemu_pop_frame) the sole
 * consumer — a lock-free SPSC ring with the same atomic discipline as the HID
 * rings (ringbuf.c). When the ring is full the producer drops the NEW frame
 * (it must NOT overwrite a slot the consumer may be mid-copy on, and it must
 * NOT write the consumer-owned read index).
 */
#define FRAME_PACKED_SIZE 2048
#define FRAME_RING_SIZE 64

/* Host poll cadence (the vault's setInterval is ~16ms). kkemu_poll() ticks the
 * firmware ms-timer this many times per call so animations advance at ~real
 * speed without relying on the (host-runtime-unreliable) SIGALRM timer. */
#define KKEMU_POLL_INTERVAL_MS 16

static uint8_t frame_ring[FRAME_RING_SIZE][FRAME_PACKED_SIZE];
static uint8_t last_packed[FRAME_PACKED_SIZE]; /* producer-only (poll thread) */
static int last_packed_valid = 0;              /* producer-only */
static uint8_t
    capture_scratch[FRAME_PACKED_SIZE];      /* producer-only pack buffer */
static _Atomic uint32_t frame_write_idx = 0; /* written by producer ONLY */
static _Atomic uint32_t frame_read_idx = 0;  /* written by consumer ONLY */

/*
 * Scratch returned by kkemu_get_display(). File-scope (not function-static)
 * so kkemu_shutdown() can zero it alongside the other display buffers.
 */
static uint8_t display_packed_scratch[FRAME_PACKED_SIZE];

/* ── Replacement I/O functions ──────────────────────────────────────── */

/*
 * These replace the UDP socket functions in emulator/udp.c.
 * When building as a shared library, we link against these instead.
 */

void libkkemu_socketInit(void) {
  ringbuf_init(&rb_main_in);
  ringbuf_init(&rb_main_out);
  ringbuf_init(&rb_debug_in);
  ringbuf_init(&rb_debug_out);
}

size_t libkkemu_socketRead(int* iface, void* buffer, size_t size) {
  if (ringbuf_pop(&rb_main_in, (uint8_t*)buffer, size)) {
    *iface = 0;
    return size < RINGBUF_SLOT_SIZE ? size : RINGBUF_SLOT_SIZE;
  }
  if (ringbuf_pop(&rb_debug_in, (uint8_t*)buffer, size)) {
    *iface = 1;
    return size < RINGBUF_SLOT_SIZE ? size : RINGBUF_SLOT_SIZE;
  }
  return 0;
}

size_t libkkemu_socketWrite(int iface, const void* buffer, size_t size) {
  RingBuf* rb = (iface == 0) ? &rb_main_out : &rb_debug_out;
  if (!ringbuf_push(rb, (const uint8_t*)buffer, size)) return 0;
  return size;
}

/* ── Display capture callback ───────────────────────────────────────── */

/*
 * Pack the 8-bpp grayscale canvas (256x64 = 16384 bytes) into the
 * 1-bit SSD1306 page format the host wants. Skip if identical to the
 * last frame we captured. Called from display_refresh() on every poll
 * and on every iteration of confirm_helper's busy loop.
 */
static void libkkemu_capture_frame(const uint8_t* canvas_buf) {
  if (!canvas_buf) return;

  /* Pack into a producer-private scratch — NOT a ring slot. When the ring is
   * full the next write slot still holds an unread frame the consumer may be
   * copying, so we must decide to publish/drop before touching it. */
  memset(capture_scratch, 0, FRAME_PACKED_SIZE);
  for (int x = 0; x < 256; x++) {
    for (int y = 0; y < 64; y++) {
      if (display_mono_pixel_is_lit(canvas_buf[y * 256 + x], x, y)) {
        capture_scratch[x + (y / 8) * 256] |= (uint8_t)(1u << (y % 8));
      }
    }
  }

  /* Dedup against the last captured frame (producer-only state). */
  if (last_packed_valid &&
      memcmp(capture_scratch, last_packed, FRAME_PACKED_SIZE) == 0) {
    return;
  }
  /* SPSC publish, drop-on-full (same discipline as ringbuf.c). The producer
   * writes only frame_write_idx; the consumer writes only frame_read_idx. When
   * not full, write%SIZE != read%SIZE (their distance is in [1, SIZE-1]), so
   * producer and consumer never touch the same slot. last_packed is updated
   * ONLY on a real publish, so a frame dropped while full can still be captured
   * on a later tick. */
  uint32_t w = atomic_load_explicit(&frame_write_idx, memory_order_relaxed);
  uint32_t r = atomic_load_explicit(&frame_read_idx, memory_order_acquire);
  if (w - r >= FRAME_RING_SIZE) return; /* full → drop the new frame */

  memcpy(frame_ring[w % FRAME_RING_SIZE], capture_scratch, FRAME_PACKED_SIZE);
  memcpy(last_packed, capture_scratch, FRAME_PACKED_SIZE);
  last_packed_valid = 1;
  atomic_store_explicit(&frame_write_idx, w + 1, memory_order_release);
}

/* ── Public API ─────────────────────────────────────────────────────── */

int kkemu_init(uint8_t* flash_buf, size_t flash_len) {
  if (flash_len != KKEMU_FLASH_SIZE) return -1;
  if (!flash_buf) return -1;
  if (libkkemu_initialized) return -1;

  /* Point firmware's flash pointer at the host-provided buffer */
  emulator_flash_base = flash_buf;

  /*
   * Lock memory to prevent secrets in the flash buffer (seed, FVK, PIN
   * derivation state) from being swapped out. Failure is non-fatal — many
   * platforms cap unprivileged mlock at a few MB (RLIMIT_MEMLOCK), and a
   * dev/CI environment that hits the cap shouldn't break emulator usage.
   * We DO log to stderr so the host can decide to escalate (raise the
   * rlimit, run with CAP_IPC_LOCK, etc.) before signing real material.
   * Production hosts of libkkemu should treat a logged failure as a
   * security warning and refuse to load secrets.
   */
#ifdef _WIN32
  if (!VirtualLock(flash_buf, flash_len)) {
    fprintf(stderr,
            "[libkkemu] VirtualLock(%zu bytes) failed (err %lu) — flash buffer "
            "may be paged to disk; do not load production secrets\n",
            flash_len, (unsigned long)GetLastError());
  }
#else
  if (mlock(flash_buf, flash_len) != 0) {
    fprintf(stderr,
            "[libkkemu] mlock(%zu bytes) failed: %s — flash buffer may be "
            "swapped to disk; do not load production secrets\n",
            flash_len, strerror(errno));
  }
#endif

  /* Initialize ring buffers (replaces UDP socket init) */
  libkkemu_socketInit();

  /* Reset frame capture state */
  frame_write_idx = 0;
  frame_read_idx = 0;
  last_packed_valid = 0;

  /* Initialize /dev/urandom for RNG */
  setup_urandom_only();

#if DEBUG_LINK && !BITCOIN_ONLY
  clearsign_root_load_test_root_from_env();
#endif

  /* Board init (timers, etc.) */
  kk_board_init();
  timer_set_poll_driven(true);

  /* Hook display_refresh() so every canvas update is captured into
   * our ring buffer. Must be set before storage_init/fsm_init/
   * layoutHomeForced so the boot screens get captured too. */
  display_set_dump_callback(libkkemu_capture_frame);

  /* Load storage from flash buffer */
  storage_init();

  /* Initialize message handler FSM */
  fsm_init();

  /* Draw initial home screen */
  layoutHomeForced();

  libkkemu_initialized = 1;
  return 0;
}

int kkemu_shutdown_timeout(uint32_t timeout_ms) {
  if (!libkkemu_initialized) return 0;

  /* Join the producer before touching firmware, rings, or host flash. */
  if (kkemu_stop_timeout(timeout_ms) != 0) return -1;

  /*
   * End any workflow still in flight BEFORE anything else.
   *
   * The buffer scrubbing below covers the transport rings and the frame ring,
   * but signing state and fsm_derived_node -- the shared derived private-key
   * scratch -- live behind fsm_abort_workflows(), which nothing here was
   * calling. In the dylib case this file is written for, the library sits in a
   * long-running host process, so a shutdown/init cycle would carry an old
   * workflow and its key material across into the next session. That is the
   * same exposure the comment below describes, and it needs the same answer.
   *
   * Before storage_commit() so the committed image reflects the aborted state
   * rather than a half-finished ceremony.
   */
  fsm_abort_workflows();

  /* Flush any pending storage to the flash buffer */
  storage_commit();

  /*
   * Zero every static buffer that could hold sensitive material before
   * we tear down. In dylib mode this library lives inside a long-running
   * host process — the static rings, frame ring, and packed-display
   * scratch can outlive the emulator session and be visible to the rest
   * of the host's memory image (core dumps, ptrace, GC roots in a Bun
   * runtime, etc.). Specifically:
   *
   *   - rb_main_in / rb_main_out:  PIN, passphrase, signing inputs/outputs
   *   - rb_debug_in / rb_debug_out: mnemonic + recovery state when
   *                                 KK_DEBUG_LINK builds are loaded
   *   - frame_ring / last_packed:  rendered OLED bytes for every screen,
   *                                including PIN matrix, recovery words,
   *                                address confirms, signing summaries
   *
   * memzero() is the trezor-crypto helper that the compiler can't optimize
   * out. Same primitive used throughout the firmware to clear key material.
   */
  memzero(&rb_main_in, sizeof(rb_main_in));
  memzero(&rb_main_out, sizeof(rb_main_out));
  memzero(&rb_debug_in, sizeof(rb_debug_in));
  memzero(&rb_debug_out, sizeof(rb_debug_out));
  memzero(frame_ring, sizeof(frame_ring));
  memzero(last_packed, sizeof(last_packed));
  memzero(capture_scratch, sizeof(capture_scratch));
  memzero(display_packed_scratch, sizeof(display_packed_scratch));
  last_packed_valid = 0;
  frame_write_idx = 0;
  frame_read_idx = 0;

  /*
   * Unlock + caller is responsible for zeroing the host-owned flash buffer
   * after this returns. We explicitly DO NOT zero it here — the host may
   * want to inspect / persist post-mortem state. Documented contract.
   */
  if (emulator_flash_base) {
#ifdef _WIN32
    VirtualUnlock(emulator_flash_base, KKEMU_FLASH_SIZE);
#else
    munlock(emulator_flash_base, KKEMU_FLASH_SIZE);
#endif
    emulator_flash_base = NULL;
  }

  libkkemu_initialized = 0;
  return 0;
}

void kkemu_shutdown(void) {
  /* Legacy callers have no way to handle a live thread on return. */
  while (kkemu_shutdown_timeout(UINT32_MAX) != 0) {
  }
}

int kkemu_write(const uint8_t* data, size_t len, int iface) {
  if (!libkkemu_initialized) return -1;
  if (len != KKEMU_PACKET_SIZE) return -1;

  RingBuf* rb = (iface == KKEMU_IFACE_MAIN) ? &rb_main_in : &rb_debug_in;
  return ringbuf_push(rb, data, len) ? 0 : -1;
}

int kkemu_read(uint8_t* buf, size_t len, int iface) {
  if (!libkkemu_initialized) return 0;
  if (len < KKEMU_PACKET_SIZE) return 0;

  RingBuf* rb = (iface == KKEMU_IFACE_MAIN) ? &rb_main_out : &rb_debug_out;
  return ringbuf_pop(rb, buf, KKEMU_PACKET_SIZE) ? KKEMU_PACKET_SIZE : 0;
}

/*
 * One iteration of the firmware event loop. Same as exec() in main.cpp:
 *   usbPoll()        — reads input, dispatches through FSM
 *   animate()        — updates screen animations
 *   display_refresh() — renders framebuffer
 *
 * usbPoll() internally calls emulatorSocketRead() which we've replaced with
 * libkkemu_socketRead() via the ring buffers.
 *
 * Drive the firmware millisecond timer from the poll on EVERY platform. The
 * dylib is caller-driven; relying on the SIGALRM/ualarm timer (which the
 * standalone kkemu binary uses) is unreliable inside the host runtime — Bun
 * does not deliver the firmware's SIGALRM, so animate_flag never flips and
 * every animation (boot logo, screensaver) stays frozen → a blank OLED at
 * rest. Tick ~one poll-interval of milliseconds so the periodic animation
 * runnable fires and animations + delay_ms() advance at roughly real speed.
 */
static void kkemu_poll_body(void) {
  for (int t = 0; t < KKEMU_POLL_INTERVAL_MS; t++) timerisr_usr();

  usbPoll();
  animate();
  display_refresh();
}

int kkemu_poll(void) {
  if (!libkkemu_initialized) return -1;
  /* Never let two threads drive the firmware core. */
  if (atomic_load(&g_poll_joinable)) return 0;
  kkemu_poll_body();
  return 0;
}

static void kkemu_sleep_ms(int ms) {
#ifdef _WIN32
  Sleep((DWORD)ms);
#else
  struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
  nanosleep(&ts, NULL);
#endif
}

static uint64_t kkemu_monotonic_ms(void) {
#ifdef _WIN32
  return GetTickCount64();
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
#endif
}

/* The poll thread holds g_fw_lock across each body call, releasing it during
 * the inter-poll sleep. While confirm_helper busy-waits for a decision the body
 * does not return, so the lock stays held for the whole confirm — but that must
 * NOT block the host: the decision is delivered through the lock-free rings,
 * and the host acquires the lock for flash snapshots via kkemu_trylock() (which
 * never blocks the host event loop). The host must never take g_fw_lock with a
 * blocking call while a confirm may be pending, or it would deadlock against
 * the very loop that needs the host alive to deliver the decision. */
static void kkemu_poll_loop(void) {
  while (POLL_RUNNING()) {
    FW_LOCK();
    if (POLL_RUNNING()) kkemu_poll_body();
    FW_UNLOCK();
    kkemu_sleep_ms(KKEMU_POLL_INTERVAL_MS);
  }
  atomic_store_explicit(&g_poll_exited, 1, memory_order_release);
}

#ifdef _WIN32
static DWORD WINAPI kkemu_poll_thread_fn(LPVOID arg) {
  (void)arg;
  kkemu_poll_loop();
  return 0;
}
#else
static void* kkemu_poll_thread_fn(void* arg) {
  (void)arg;
  kkemu_poll_loop();
  return NULL;
}
#endif

/* Cancel wakes a parked confirm. Retry within the caller's deadline. */
/* '?##', MessageType_Cancel (20), payload length 0. */
static const uint8_t kkemu_cancel_frame[KKEMU_PACKET_SIZE] = {0x3F, 0x23, 0x23,
                                                              0x00, 0x14};

static int kkemu_inject_cancel(uint64_t deadline) {
  do {
    if (ringbuf_push(&rb_main_in, kkemu_cancel_frame, KKEMU_PACKET_SIZE))
      return 1;
    if (kkemu_monotonic_ms() >= deadline) return 0;
    kkemu_sleep_ms(1);
  } while (!atomic_load_explicit(&g_poll_exited, memory_order_acquire));
  return 0;
}

/* After POLL_SET(0): 1 if the thread is between bodies and needs no Cancel
 * (a stray Cancel would draw an unsolicited Failure). */
static int kkemu_poll_body_quiesced(uint64_t deadline) {
  for (int i = 0; i < 2 * KKEMU_POLL_INTERVAL_MS; i++) {
    if (FW_TRYLOCK()) {
      FW_UNLOCK();
      return 1;
    }
    if (kkemu_monotonic_ms() >= deadline) return 0;
    kkemu_sleep_ms(1);
  }
  return 0;
}

/* Drop an unread wake Cancel (newest slot) so the next session does not
 * answer it with an unsolicited Failure. */
static void kkemu_discard_unread_cancel(void) {
  uint32_t head = atomic_load_explicit(&rb_main_in.head, memory_order_relaxed);
  uint32_t last = (head + RINGBUF_CAPACITY - 1) % RINGBUF_CAPACITY;
  if (!ringbuf_empty(&rb_main_in) &&
      memcmp(rb_main_in.data[last], kkemu_cancel_frame, KKEMU_PACKET_SIZE) == 0)
    atomic_store_explicit(&rb_main_in.head, last, memory_order_release);
}

int kkemu_start(void) {
  if (!libkkemu_initialized) return -1;
  if (atomic_load(&g_poll_joinable)) return POLL_RUNNING() ? 0 : -1;
  atomic_store(&g_poll_exited, 0);
  atomic_store(&g_poll_joinable, 1);
  g_stop_cancel_injected = 0;

#ifdef _WIN32
  if (!g_fw_lock_ready) {
    InitializeCriticalSection(&g_fw_lock);
    g_fw_lock_ready = 1;
  }
  POLL_SET(1);
  g_poll_thread = CreateThread(NULL, 0, kkemu_poll_thread_fn, NULL, 0, NULL);
  if (!g_poll_thread) {
    POLL_SET(0);
    atomic_store(&g_poll_joinable, 0);
    return -1;
  }
#else
  POLL_SET(1);
  if (pthread_create(&g_poll_thread, NULL, kkemu_poll_thread_fn, NULL) != 0) {
    POLL_SET(0);
    atomic_store(&g_poll_joinable, 0);
    return -1;
  }
#endif
  return 0;
}

int kkemu_stop_timeout(uint32_t timeout_ms) {
  if (!atomic_load(&g_poll_joinable)) return 0;

  uint64_t deadline = kkemu_monotonic_ms() + timeout_ms;
  POLL_SET(0);
  if (!g_stop_cancel_injected && !kkemu_poll_body_quiesced(deadline))
    g_stop_cancel_injected = kkemu_inject_cancel(deadline);
#ifdef _WIN32
  if (g_poll_thread) {
    uint64_t now = kkemu_monotonic_ms();
    DWORD remaining = now < deadline ? (DWORD)(deadline - now) : 0;
    /* INFINITE is a sentinel, not a finite timeout. */
    if (remaining == INFINITE) --remaining;
    if (WaitForSingleObject(g_poll_thread, remaining) != WAIT_OBJECT_0)
      return -1;
    CloseHandle(g_poll_thread);
    g_poll_thread = NULL;
  }
  /* Not deleted: the host may still hold it and must be able to release it. */
#else
  /* macOS has no pthread_timedjoin_np. Wait for the thread's final release
   * publication before joining; no firmware work remains after publication. */
  while (!atomic_load_explicit(&g_poll_exited, memory_order_acquire)) {
    if (kkemu_monotonic_ms() >= deadline) return -1;
    kkemu_sleep_ms(1);
  }
  pthread_join(g_poll_thread, NULL);
#endif
  if (g_stop_cancel_injected) kkemu_discard_unread_cancel();
  g_stop_cancel_injected = 0;
  atomic_store(&g_poll_joinable, 0);
  return 0;
}

void kkemu_stop(void) {
  /* Preserve the legacy void API: returning with a live thread would let
   * existing callers unload its code or free its flash. New hosts use the
   * checked timeout APIs and retain both resources when they return -1. */
  while (kkemu_stop_timeout(UINT32_MAX) != 0) {
  }
}

/* Host-side guard for reading the shared flash buffer (saveFlash) without
 * tearing a concurrent storage_commit on the poll thread. No-op when the
 * thread isn't running (single-threaded test path needs no lock).
 *
 * WARNING: kkemu_lock() BLOCKS, and the poll thread can hold g_fw_lock for the
 * whole duration of a pending confirm. The host must therefore NOT call
 * kkemu_lock() from a thread/loop that also has to stay alive to deliver the
 * confirm decision (it would deadlock). Use kkemu_trylock() + an event-loop
 * yield there instead. kkemu_lock() is retained for paths with no pending
 * confirm. */
void kkemu_lock(void) {
  if (!atomic_load(&g_poll_joinable)) return;
  FW_LOCK();
  HOST_HOLDS_SET(1);
}

void kkemu_unlock(void) {
  if (!HOST_HOLDS_LOCK()) return;
  HOST_HOLDS_SET(0);
  FW_UNLOCK();
}

/* Non-blocking acquire. Returns 1 if the firmware lock is now held by the
 * caller (balance with kkemu_unlock()), 0 if it is currently held by the poll
 * thread (e.g. mid-confirm) — the caller should yield its event loop and retry,
 * which keeps the loop alive to deliver the decision that releases the lock.
 * No-op success (returns 1, nothing to unlock) when the thread isn't running.
 */
int kkemu_trylock(void) {
  if (HOST_HOLDS_LOCK()) return 0;
  if (!atomic_load(&g_poll_joinable)) return 1;
  if (!FW_TRYLOCK()) return 0;
  HOST_HOLDS_SET(1);
  return 1;
}

/*
 * Snapshot the current OLED canvas into packed SSD1306 format (byte index =
 * x + (y/8)*256, bit = y%8). Host-driven convenience used by the python
 * screenshot harness, which drives the firmware single-threaded via kkemu_poll.
 *
 * WARNING: NOT thread-safe. It reads the live firmware canvas directly with no
 * synchronization against the poll thread, so it is only safe in HOST-DRIVEN
 * mode (no kkemu_start). In thread-driven mode the canonical, race-free way to
 * observe the display is the SPSC capture ring via kkemu_pop_frame(); do not
 * wire kkemu_get_display into a threaded host.
 */
const uint8_t* kkemu_get_display(int* width, int* height) {
  if (!libkkemu_initialized) {
    if (width) *width = 0;
    if (height) *height = 0;
    return NULL;
  }

  const Canvas* c = display_canvas();
  if (!c || !c->buffer) {
    if (width) *width = 0;
    if (height) *height = 0;
    return NULL;
  }

  memset(display_packed_scratch, 0, sizeof(display_packed_scratch));
  for (int x = 0; x < 256; x++) {
    for (int y = 0; y < 64; y++) {
      /* Same "lit" definition as the capture ring above and as the DebugLink
       * screenshot path (fsm_msg_debug.h) — all three 1-bit serialisers must
       * agree or the same canvas packs to two different 2048-byte images
       * depending on which entry point the host called. The naive `> 0` this
       * replaced erased foreground glyphs drawn over a dim animation
       * background (PIN matrix, recovery cipher grid); see the rationale on
       * display_mono_pixel_is_lit() in keepkey_display.h. */
      if (display_mono_pixel_is_lit(c->buffer[y * 256 + x], x, y)) {
        display_packed_scratch[x + (y / 8) * 256] |= (uint8_t)(1u << (y % 8));
      }
    }
  }

  if (width) *width = 256;
  if (height) *height = 64;
  return display_packed_scratch;
}

int kkemu_pop_frame(uint8_t* out_packed) {
  if (!libkkemu_initialized || !out_packed) return 0;
  /* SPSC consume: read frame_read_idx (we own it) and frame_write_idx (acquire,
   * to see the producer's slot write). Empty when the indices are equal. */
  uint32_t r = atomic_load_explicit(&frame_read_idx, memory_order_relaxed);
  uint32_t w = atomic_load_explicit(&frame_write_idx, memory_order_acquire);
  if (r == w) return 0;
  memcpy(out_packed, frame_ring[r % FRAME_RING_SIZE], FRAME_PACKED_SIZE);
  atomic_store_explicit(&frame_read_idx, r + 1, memory_order_release);
  return 1;
}

int kkemu_is_running(void) { return libkkemu_initialized; }
