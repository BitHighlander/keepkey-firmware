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
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/rand/rng.h"
#include "ringbuf.h"

#include <string.h>
#include <sys/mman.h>

/* Defined in firmware — we just need the declaration */
extern void fsm_init(void);

/* ── Ring buffers (replace UDP sockets) ─────────────────────────────── */

static RingBuf rb_main_in;    /* host → firmware (main interface) */
static RingBuf rb_main_out;   /* firmware → host (main interface) */
static RingBuf rb_debug_in;   /* host → firmware (debug link) */
static RingBuf rb_debug_out;  /* firmware → host (debug link) */

static int libkkemu_initialized = 0;

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

size_t libkkemu_socketRead(int *iface, void *buffer, size_t size) {
    if (ringbuf_pop(&rb_main_in, (uint8_t *)buffer, size)) {
        *iface = 0;
        return size < RINGBUF_SLOT_SIZE ? size : RINGBUF_SLOT_SIZE;
    }
    if (ringbuf_pop(&rb_debug_in, (uint8_t *)buffer, size)) {
        *iface = 1;
        return size < RINGBUF_SLOT_SIZE ? size : RINGBUF_SLOT_SIZE;
    }
    return 0;
}

size_t libkkemu_socketWrite(int iface, const void *buffer, size_t size) {
    RingBuf *rb = (iface == 0) ? &rb_main_out : &rb_debug_out;
    if (!ringbuf_push(rb, (const uint8_t *)buffer, size))
        return 0;
    return size;
}

/* ── Public API ─────────────────────────────────────────────────────── */

int kkemu_init(uint8_t *flash_buf, size_t flash_len) {
    if (flash_len != KKEMU_FLASH_SIZE) return -1;
    if (!flash_buf) return -1;
    if (libkkemu_initialized) return -1;

    /* Point firmware's flash pointer at the host-provided buffer */
    emulator_flash_base = flash_buf;

    /* Lock memory to prevent swapping secrets to disk */
    mlock(flash_buf, flash_len);

    /* Initialize ring buffers (replaces UDP socket init) */
    libkkemu_socketInit();

    /* Initialize /dev/urandom for RNG */
    setup_urandom_only();

    /* Board init (timers, etc.) */
    kk_board_init();

    /* Load storage from flash buffer */
    storage_init();

    /* Initialize message handler FSM */
    fsm_init();

    /* Draw initial home screen */
    layoutHomeForced();

    libkkemu_initialized = 1;
    return 0;
}

void kkemu_shutdown(void) {
    if (!libkkemu_initialized) return;

    /* Flush any pending storage to the flash buffer */
    storage_commit();

    /* Unlock memory (host should zero + free after this) */
    if (emulator_flash_base) {
        munlock(emulator_flash_base, KKEMU_FLASH_SIZE);
        emulator_flash_base = NULL;
    }

    libkkemu_initialized = 0;
}

int kkemu_write(const uint8_t *data, size_t len, int iface) {
    if (!libkkemu_initialized) return -1;
    if (len != KKEMU_PACKET_SIZE) return -1;

    RingBuf *rb = (iface == KKEMU_IFACE_MAIN) ? &rb_main_in : &rb_debug_in;
    return ringbuf_push(rb, data, len) ? 0 : -1;
}

int kkemu_read(uint8_t *buf, size_t len, int iface) {
    if (!libkkemu_initialized) return 0;
    if (len < KKEMU_PACKET_SIZE) return 0;

    RingBuf *rb = (iface == KKEMU_IFACE_MAIN) ? &rb_main_out : &rb_debug_out;
    return ringbuf_pop(rb, buf, KKEMU_PACKET_SIZE) ? KKEMU_PACKET_SIZE : 0;
}

int kkemu_poll(void) {
    if (!libkkemu_initialized) return -1;

    /*
     * This is the same as exec() in main.cpp:
     *   usbPoll()       — reads input, dispatches through FSM
     *   animate()        — updates screen animations
     *   display_refresh() — renders framebuffer
     *
     * usbPoll() internally calls emulatorSocketRead() which we've
     * replaced with libkkemu_socketRead() via the ring buffers.
     */
    usbPoll();
    animate();
    display_refresh();

    return 0;
}

const uint8_t *kkemu_get_display(int *width, int *height) {
    /*
     * Pack the firmware's 8-bpp grayscale canvas (256×64 = 16384 bytes) into
     * the 1-bit packed layout vault expects (2048 bytes). Same format
     * DebugLinkGetState.layout uses: byte index = x + (y/8)*256,
     * bit within byte = y%8 (LSB = top row of the 8-pixel column).
     */
    static uint8_t packed[2048];

    if (!libkkemu_initialized) { if (width) *width = 0; if (height) *height = 0; return NULL; }

    const Canvas *c = display_canvas();
    if (!c || !c->buffer) { if (width) *width = 0; if (height) *height = 0; return NULL; }

    memset(packed, 0, sizeof(packed));
    for (int x = 0; x < 256; x++) {
        for (int y = 0; y < 64; y++) {
            if (c->buffer[y * 256 + x] > 0) {
                packed[x + (y / 8) * 256] |= (uint8_t)(1u << (y % 8));
            }
        }
    }

    if (width)  *width = 256;
    if (height) *height = 64;
    return packed;
}

int kkemu_is_running(void) {
    return libkkemu_initialized;
}
