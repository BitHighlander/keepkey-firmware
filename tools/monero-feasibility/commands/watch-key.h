#ifndef KEEPKEY_MONERO_RESEARCH_WATCH_KEY_H
#define KEEPKEY_MONERO_RESEARCH_WATCH_KEY_H

#include "monero_research.h"

/* Internal research helper: caller must obtain explicit export consent first.
 * Never returns the private spend key. Clears outputs on failure. */
bool monero_research_get_watch_key(
    const uint8_t node_key[32], uint32_t network, uint8_t watch_key[32],
    char address[MONERO_RESEARCH_ADDRESS_CAPACITY]);

#endif
