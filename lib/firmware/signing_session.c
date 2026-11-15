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

#include "keepkey/firmware/signing_session.h"

#include "trezor/crypto/memzero.h"

#if ZCASH_PRIVACY && MONERO_SIGNING
_Static_assert(MONERO_SESSION_BYTES <= sizeof(ZcashSigningState),
               "Monero must fit the Zcash session's footprint");
#endif

SigningSessionArena CONFIDENTIAL signing_session_arena;

/* Not secret, and in ordinary .bss so it is FREE at every boot. */
static uint8_t owner_tag;

void* signing_session_claim(SigningSessionOwner owner) {
  if (owner == SIGNING_SESSION_FREE) return NULL;
  if (owner_tag != SIGNING_SESSION_FREE && owner_tag != (uint8_t)owner)
    return NULL;
  memzero(&signing_session_arena, sizeof(signing_session_arena));
  owner_tag = (uint8_t)owner;
  return &signing_session_arena;
}

void* signing_session_get(SigningSessionOwner owner) {
  if (owner == SIGNING_SESSION_FREE || owner_tag != (uint8_t)owner) return NULL;
  return &signing_session_arena;
}

void signing_session_release(SigningSessionOwner owner) {
  if (owner == SIGNING_SESSION_FREE || owner_tag != (uint8_t)owner) return;
  memzero(&signing_session_arena, sizeof(signing_session_arena));
  owner_tag = SIGNING_SESSION_FREE;
}

SigningSessionOwner signing_session_owner(void) {
  return (SigningSessionOwner)owner_tag;
}

#if DEBUG_LINK
bool signing_session_is_zero(void) {
  const uint8_t* bytes = (const uint8_t*)&signing_session_arena;
  uint8_t aggregate = 0;
  for (size_t i = 0; i < sizeof(signing_session_arena); ++i)
    aggregate |= bytes[i];
  return aggregate == 0;
}
#endif
