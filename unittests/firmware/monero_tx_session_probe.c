/* Compile the engine with an interrupt at its timestamp sample. */
#include "keepkey/board/timer.h"
void (*monero_session_interrupt)(void);
static uint32_t interrupt_time(void) {
  if (monero_session_interrupt) monero_session_interrupt();
  return getSysTime();
}
#define getSysTime interrupt_time
#define monero_tx_result_text probe_monero_tx_result_text
#define monero_tx_active probe_monero_tx_active
#define monero_tx_progress probe_monero_tx_progress
#define monero_tx_next_output_proves probe_monero_tx_next_output_proves
#define monero_tx_review probe_monero_tx_review
#define monero_tx_begin probe_monero_tx_begin
#define monero_tx_set_input probe_monero_tx_set_input
#define monero_tx_input_vini probe_monero_tx_input_vini
#define monero_tx_all_inputs_set probe_monero_tx_all_inputs_set
#define monero_tx_set_output probe_monero_tx_set_output
#define monero_tx_all_out_set probe_monero_tx_all_out_set
#define monero_tx_sign_input probe_monero_tx_sign_input
#define monero_tx_final probe_monero_tx_final
#include "../../lib/firmware/monero_tx.c"
