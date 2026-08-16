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

#ifndef KEEPKEY_FIRMWARE_SIGNED_METADATA_H
#define KEEPKEY_FIRMWARE_SIGNED_METADATA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Signer keyring for host-supplied, signer-attested metadata.
 *
 * This release ships the keyring interface but no way to populate it: the
 * messages that load signers are not registered, so every slot is empty and
 * every attestation check below fails closed. Callers must therefore treat
 * host-supplied token symbols and instruction schemas as unverified, which is
 * what the Solana review path already does -- it only consults a signer after
 * verification succeeds.
 *
 * The full clear-signing engine replaces this translation unit; the signatures
 * here are the ones it implements, so nothing above this line changes when it
 * lands. */

#define METADATA_MAX_KEYS 4
#define METADATA_FINGERPRINT_LEN 9

/* Human-readable name for a loaded signer, or NULL when the slot is empty. */
const char* signed_metadata_signer_alias(uint8_t key_id);

/* Short fingerprint of a loaded signer's public key. Aliases are host-chosen
 * and not unique; the fingerprint is what actually identifies the key.
 * Returns false when the slot is empty. */
bool signed_metadata_signer_fingerprint(uint8_t key_id,
                                        char out[METADATA_FINGERPRINT_LEN]);

/* True when the signer in this slot was loaded at runtime rather than being
 * pinned into the firmware image. */
bool signed_metadata_signer_is_runtime(uint8_t key_id);

/* Verify `sig` over `data` against the signer in `key_id`. */
bool signed_metadata_verify_attestation(uint8_t key_id, const uint8_t* data,
                                        size_t data_len, const uint8_t* sig,
                                        size_t sig_len);

#endif
