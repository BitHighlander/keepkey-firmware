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

#include "keepkey/firmware/signed_metadata.h"

/* Empty signer keyring.
 *
 * Signers are loaded over the wire, and the messages that do so are not
 * registered in this release, so no slot can ever be populated. Rather than
 * pretend otherwise, every query answers "no signer" and every attestation
 * fails. That is the safe direction: an unverified token symbol is shown as
 * unverified, and an instruction schema that cannot be attested is rejected
 * rather than trusted.
 *
 * Deliberately not a stub that will silently start passing -- when the
 * clear-signing engine lands it replaces this file wholesale, and until then
 * there is no configuration in which these return anything else. */

const char* signed_metadata_signer_alias(uint8_t key_id) {
  (void)key_id;
  return 0;
}

bool signed_metadata_signer_fingerprint(uint8_t key_id,
                                        char out[METADATA_FINGERPRINT_LEN]) {
  (void)key_id;
  (void)out;
  return false;
}

bool signed_metadata_signer_is_runtime(uint8_t key_id) {
  (void)key_id;
  return false;
}

bool signed_metadata_verify_attestation(uint8_t key_id, const uint8_t* data,
                                        size_t data_len, const uint8_t* sig,
                                        size_t sig_len) {
  (void)key_id;
  (void)data;
  (void)data_len;
  (void)sig;
  (void)sig_len;
  return false;
}
