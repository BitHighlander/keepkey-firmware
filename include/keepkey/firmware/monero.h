/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef KEEPKEY_FIRMWARE_MONERO_H
#define KEEPKEY_FIRMWARE_MONERO_H

/* Monero wallet keys, addresses and key-image sync. Full builds only
 * (MONERO_SIGNING). The wallet is m/44'/128'/account' (SLIP-10 ed25519):
 * the spend secret b is the node key reduced mod l (Trezor convention, never
 * hashed first), the view secret a = Hs(b). Within that wallet, (major,
 * minor) select a subaddress; (0, 0) is the primary address. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "messages-monero.pb.h"

#define MONERO_ADDRESS_LENGTH 95u
#define MONERO_ADDRESS_CAPACITY 96u
#define MONERO_KEY_IMAGE_MAX_OUTPUTS 64u

/* Exactly m/44'/128'/account'. */
bool monero_path_valid(const uint32_t* path, size_t count);

/* "Mainnet", "Testnet", "Stagenet", or NULL for anything else. */
const char* monero_network_name(uint32_t network);

/* The base58 address of subaddress (major, minor), NUL terminated. node_key
 * is the SLIP-10 private node key. Clears `address` on failure. */
bool monero_get_address(const uint8_t node_key[32], uint32_t network,
                        uint32_t major, uint32_t minor,
                        char address[MONERO_ADDRESS_CAPACITY]);

/* The private view key of the wallet, and the (major, 0) address it is shown
 * with. The caller must have the user's consent first. Never returns the
 * spend key. Clears both outputs on failure. */
bool monero_get_watch_key(const uint8_t node_key[32], uint32_t network,
                          uint32_t major, uint8_t view_key[32],
                          char address[MONERO_ADDRESS_CAPACITY]);

/* Key-image sync. The session lives in the shared signing-session arena
 * (owner SIGNING_SESSION_MONERO_KEY_IMAGE) and expires 120 s after it began.
 * Every failure ends it and wipes it; only a complete, correctly bound
 * transcript releases the encryption key. */
bool monero_key_image_active(void);
bool monero_key_image_begin(const uint8_t node_key[32],
                            const MoneroKeyImageExportInitRequest* request);
/* permil: outputs done so far, in thousandths of the total. */
bool monero_key_image_step(const MoneroKeyImageSyncStepRequest* request,
                           MoneroKeyImageSyncStepAck* response,
                           uint32_t* permil);
bool monero_key_image_finish(uint8_t encryption_key[32]);

/* End every Monero session and wipe it. */
void monero_session_abort(void);

#endif
