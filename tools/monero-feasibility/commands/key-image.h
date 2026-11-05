#ifndef KEEPKEY_MONERO_KEY_IMAGE_RESEARCH_H
#define KEEPKEY_MONERO_KEY_IMAGE_RESEARCH_H

#include "monero_research.h"
#include "research-schema.h"

#define MONERO_KEY_IMAGE_MAX_OUTPUTS 64u

bool monero_key_image_active(void);
void monero_key_image_abort(void);
bool monero_key_image_state_is_zero(void);
bool monero_key_image_begin(const uint8_t node_key[32],
                            const MoneroKeyImageExportInitRequest* request);
bool monero_key_image_step(const MoneroKeyImageSyncStepRequest* request,
                           MoneroKeyImageSyncStepAck* response);
bool monero_key_image_finish(uint8_t encryption_key[32]);

#endif
