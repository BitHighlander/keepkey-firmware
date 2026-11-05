/* PREPARATION ONLY: an unsigned image for a disposable tester.
 * Runs fixed public fixtures after board initialization; never returns into
 * model programming, DRBG/storage initialization, wallet APIs, or USB setup.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/supervise.h"
#include "keepkey/board/timer.h"

#ifndef MONERO_HARDWARE_CASE_COUNT
#error "hardware selftest needs the public fixture subset count"
#endif

extern uint8_t _ebss[];
extern uint32_t monero_paint_stack(uint8_t *first);
extern int monero_interop_run(void);
extern volatile uint32_t monero_checks;
extern volatile uint32_t monero_fail_line;
extern volatile uint32_t monero_phase;
extern void __real_kk_board_init(void);

/* Readable by a debugger; no USB result route or storage operation exists. */
static volatile struct {
  uint32_t magic;
  uint32_t completed;
  uint32_t status;
  uint32_t case_count;
  uint32_t checks;
  uint32_t fail_line;
  uint32_t phase;
  uint32_t elapsed_ticks;
  uint32_t painted_bottom;
  uint32_t painted_top;
  uint32_t stack_highwater_bytes;
  uint32_t paint_exhausted;
} monero_hardware_report;

__attribute__((noreturn)) void __wrap_kk_board_init(void) {
  __real_kk_board_init();
  layout_standard_notification("Monero selftest", "Running public fixtures",
                               NOTIFICATION_INFO);
  display_refresh();
  monero_hardware_report.magic = 0x584d5232u;
  monero_hardware_report.case_count = MONERO_HARDWARE_CASE_COUNT;
  monero_hardware_report.painted_bottom = (uint32_t)(uintptr_t)_ebss;
  monero_hardware_report.painted_top = monero_paint_stack(_ebss);

  uint32_t begin = getSysTime();
  int status = monero_interop_run();
  uint32_t elapsed = getSysTime() - begin;
  /* Freeze interrupts during scan. The disabling call's frame is included.
   * Measurements cover the test chain plus interruptions on this stack;
   * they exclude startup/UI and the separate protected handler stack. */
  svc_disable_interrupts();
  const volatile uint8_t *cursor = _ebss;
  const volatile uint8_t *top =
      (const volatile uint8_t *)(uintptr_t)monero_hardware_report.painted_top;
  while (cursor < top && *cursor == 0xa5) ++cursor;
  monero_hardware_report.stack_highwater_bytes = (uint32_t)(top - cursor);
  monero_hardware_report.paint_exhausted = cursor == _ebss;
  monero_hardware_report.status = (uint32_t)status;
  monero_hardware_report.checks = monero_checks;
  monero_hardware_report.fail_line = monero_fail_line;
  monero_hardware_report.phase = monero_phase;
  monero_hardware_report.elapsed_ticks = elapsed;
  monero_hardware_report.completed = 1;
  svc_enable_interrupts();

  char body[128];
  if (status) {
    snprintf(body, sizeof(body), "FAIL line %lu case %lu\nChecks %lu ticks %lu\nStack %lu bytes",
             (unsigned long)monero_fail_line, (unsigned long)monero_phase,
             (unsigned long)monero_checks, (unsigned long)elapsed,
             (unsigned long)monero_hardware_report.stack_highwater_bytes);
  } else {
    snprintf(body, sizeof(body), "PASS %lu checks\nTicks %lu\nStack %lu bytes%s",
             (unsigned long)monero_checks, (unsigned long)elapsed,
             (unsigned long)monero_hardware_report.stack_highwater_bytes,
             monero_hardware_report.paint_exhausted ? " FULL" : "");
  }
  layout_standard_notification("Monero selftest", body, NOTIFICATION_INFO);
  display_refresh();
  for (;;) {
    __asm__ volatile("wfi");
  }
}
