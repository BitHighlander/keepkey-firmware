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

/* User-provisioned metadata signing key management. Handlers for
 * AddMetadataKey, RemoveMetadataKey, ListMetadataKeys. Slots 4..6 are
 * user-writable; slots 0..3 are firmware-baked and not enumerated here. */

static void metadata_pubkey_fingerprint(const uint8_t pubkey[33],
                                        char fp_out[9]) {
  uint8_t digest[32];
  sha256_Raw(pubkey, 33, digest);
  /* First 4 bytes → 8 hex chars. Stable, short enough for OLED. */
  for (int i = 0; i < 4; i++) {
    snprintf(fp_out + i * 2, 3, "%02x", digest[i]);
  }
  fp_out[8] = '\0';
}

void fsm_msgAddMetadataKey(const AddMetadataKey *msg) {
  CHECK_INITIALIZED

  if (msg->slot < METADATA_USER_KEY_FIRST ||
      msg->slot > METADATA_USER_KEY_LAST) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "slot must be in user range (4..6)");
    layoutHome();
    return;
  }
  if (msg->pubkey.size != 33 ||
      (msg->pubkey.bytes[0] != 0x02 && msg->pubkey.bytes[0] != 0x03)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "pubkey must be 33-byte compressed secp256k1");
    layoutHome();
    return;
  }
  if (msg->label[0] == '\0') {
    fsm_sendFailure(FailureType_Failure_SyntaxError, "label must not be empty");
    layoutHome();
    return;
  }

  char fp[9];
  metadata_pubkey_fingerprint(msg->pubkey.bytes, fp);

  /* Confirm 1: slot + label. Lets user abort cheaply before PIN. */
  if (!confirm(ButtonRequestType_ButtonRequest_Other, "Add Insight Key",
               "Slot %lu\n%s", (unsigned long)msg->slot, msg->label)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Add metadata key cancelled");
    layoutHome();
    return;
  }

  /* Confirm 2: fingerprint. User verifies against company-published value
   * out-of-band. Truncating to 8 hex chars is intentional — full SHA256
   * doesn't fit and the threat model here is mistake/typo, not collision. */
  if (!confirm(ButtonRequestType_ButtonRequest_Other, "Verify Key Fingerprint",
               "fp:\n%s", fp)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Add metadata key cancelled");
    layoutHome();
    return;
  }

  CHECK_PIN_UNCACHED

  if (!storage_setMetadataKey(msg->slot, msg->pubkey.bytes, msg->label)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Could not store metadata key");
    layoutHome();
    return;
  }
  storage_commit();

  fsm_sendSuccess("Metadata key added");
  layoutHome();
}

void fsm_msgRemoveMetadataKey(const RemoveMetadataKey *msg) {
  CHECK_INITIALIZED

  if (msg->slot < METADATA_USER_KEY_FIRST ||
      msg->slot > METADATA_USER_KEY_LAST) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "slot must be in user range (4..6)");
    layoutHome();
    return;
  }

  uint8_t pubkey[33];
  char label[17];
  if (!storage_getMetadataKey(msg->slot, pubkey, label)) {
    fsm_sendFailure(FailureType_Failure_DataError, "slot is empty");
    layoutHome();
    return;
  }

  /* Show fingerprint of the key being removed — defends against stealth
   * removal where an attacker briefly accesses an unlocked device. */
  char fp[9];
  metadata_pubkey_fingerprint(pubkey, fp);

  if (!confirm(ButtonRequestType_ButtonRequest_Other, "Remove Insight Key",
               "Slot %lu: %s\nfp: %s", (unsigned long)msg->slot, label, fp)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Remove metadata key cancelled");
    layoutHome();
    return;
  }

  CHECK_PIN_UNCACHED

  if (!storage_removeMetadataKey(msg->slot)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Could not remove metadata key");
    layoutHome();
    return;
  }
  storage_commit();

  fsm_sendSuccess("Metadata key removed");
  layoutHome();
}

void fsm_msgListMetadataKeys(const ListMetadataKeys *msg) {
  (void)msg;
  RESP_INIT(MetadataKeysList);

  size_t count = 0;
  for (uint32_t slot = METADATA_USER_KEY_FIRST; slot <= METADATA_USER_KEY_LAST;
       ++slot) {
    uint8_t pubkey[33];
    char label[17];
    if (!storage_getMetadataKey(slot, pubkey, label)) continue;

    MetadataKeyType *k = &resp->keys[count++];
    memzero(k, sizeof(*k));
    k->has_slot = true;
    k->slot = slot;
    k->has_pubkey = true;
    k->pubkey.size = 33;
    memcpy(k->pubkey.bytes, pubkey, 33);
    k->has_label = true;
    strlcpy(k->label, label, sizeof(k->label));
  }
  resp->keys_count = count;

  msg_write(MessageType_MessageType_MetadataKeysList, resp);
}
