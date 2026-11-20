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

#ifndef KEEPKEY_FIRMWARE_SIGNING_SESSION_H
#define KEEPKEY_FIRMWARE_SIGNING_SESSION_H

/* One CONFIDENTIAL arena, time-shared by the engines whose sessions are too
 * large to keep side by side: Zcash shielded signing and Monero. Separate
 * sessions do not fit the RAM budget (the stack reserve must stay at least
 * 16 KiB), and the engines never run at the same time: any new top-level
 * request ends every signing engine before its handler runs.
 *
 * The owner tag says whose bytes are in the arena. An engine reads the arena
 * only while it owns it, so one engine's bytes are never taken for another's
 * state (Monero bytes aliasing zcash_signing.active, say). */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
  SIGNING_SESSION_FREE = 0,
  SIGNING_SESSION_ZCASH = 1,
  SIGNING_SESSION_MONERO_KEY_IMAGE = 2,
  SIGNING_SESSION_MONERO_TX = 3,
} SigningSessionOwner;

#if ZCASH_PRIVACY || MONERO_SIGNING

#if ZCASH_PRIVACY
#include "keepkey/firmware/zcash_signing_state.h"
#endif

/* The Monero share of the arena: the key-image sync session or the streamed
 * signing session, one at a time. The signing session (monero_tx.c) is
 * 1,440 B on the device: two Keccak contexts, the wallet keys, the session
 * keys, the input order, the mask sums and the two outputs' masks, amounts
 * and commitments. Each Monero session static-asserts that it fits. On
 * builds with Zcash this is smaller than the Zcash session, so Monero adds
 * no RAM (asserted in signing_session.c). */
#define MONERO_SESSION_BYTES 2048u

typedef union {
#if ZCASH_PRIVACY
  ZcashSigningState zcash;
#endif
#if MONERO_SIGNING
  uint64_t monero[MONERO_SESSION_BYTES / sizeof(uint64_t)];
#endif
} SigningSessionArena;

/* Only fsm_msg_zcash.h touches this directly, through zcash_signing, and only
 * after zcash_signing_is_active() checked the owner. Others use claim/get. */
extern SigningSessionArena signing_session_arena;

/* Take the arena for `owner`: wiped, then tagged. Refused (NULL) while a
 * different engine owns it; that engine must be ended first. Claiming again
 * as the current owner wipes and restarts. */
void* signing_session_claim(SigningSessionOwner owner);

/* Reserve a wiped arena without publishing it to activity/interrupt readers.
 * Release also wipes a reservation if initialization fails. Only normal
 * handler context may prepare, publish or release. */
void* signing_session_prepare(SigningSessionOwner owner);
void signing_session_publish(SigningSessionOwner owner);

/* The arena if `owner` holds a published session, else NULL. */
void* signing_session_get(SigningSessionOwner owner);

/* Wipe and free the arena if `owner` holds it; otherwise leave it alone. */
void signing_session_release(SigningSessionOwner owner);

SigningSessionOwner signing_session_owner(void);

#if DEBUG_LINK
/* True when every arena byte is zero (wipe observer for tests). */
bool signing_session_is_zero(void);
#endif

#endif /* ZCASH_PRIVACY || MONERO_SIGNING */

#endif
