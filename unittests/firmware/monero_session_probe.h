#pragma once
#include "keepkey/firmware/monero.h"
#include "keepkey/firmware/monero_tx.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Source probes inject a button interrupt at timestamp/RNG calls without
 * putting test hooks into firmware. The real session arena is shared. */
extern void (*monero_session_interrupt)(void);
MoneroTxResult probe_monero_tx_begin(const uint8_t*, const MoneroTxInitRequest*,
                                    const uint8_t*, MoneroTxInitAck*);
bool probe_monero_key_image_begin(const uint8_t*, const MoneroKeyImageExportInitRequest*);
bool probe_monero_key_image_step(const MoneroKeyImageSyncStepRequest*,
                                MoneroKeyImageSyncStepAck*, uint32_t*);
#ifdef __cplusplus
}
#endif
