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

/* Monero address, view-key export and key-image sync. Included in fsm.c,
 * full builds only. No private node or key is held across a confirmation
 * wait: each handler derives, scrubs, asks, and rederives if it must. */

#include "keepkey/firmware/monero.h"

/* Validates the path and network; on failure answers and returns false. */
static bool monero_check_request(const uint32_t* address_n, size_t count,
                                 bool has_network, uint32_t network) {
  if (!monero_path_valid(address_n, count)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Expected Monero path m/44'/128'/account'"));
    layoutHome();
    return false;
  }
  if (!monero_network_name(has_network ? network : 0)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid Monero network"));
    layoutHome();
    return false;
  }
  return true;
}

/* "Monero <network>\n<path>", for the start of a confirmation body. */
static bool monero_describe(char* out, size_t size, const uint32_t* address_n,
                            size_t count, uint32_t network) {
  char path[NODE_STRING_LENGTH] = {0};
  if (!bip32_path_to_string(path, sizeof(path), address_n, count)) return false;
  const int n =
      snprintf(out, size, "Monero %s\n%s", monero_network_name(network), path);
  return n >= 0 && (size_t)n < size;
}

void fsm_msgMoneroGetAddress(const MoneroGetAddress* msg) {
  CHECK_INITIALIZED
  if (!monero_check_request(msg->address_n, msg->address_n_count,
                            msg->has_network_type, msg->network_type))
    return;
  /* Integrated addresses are not built yet. Refuse even an empty payment
   * ID, so a host never takes a plain address for an integrated one. */
  if (msg->has_payment_id) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Monero integrated addresses are not supported"));
    layoutHome();
    return;
  }
  const uint32_t network = msg->has_network_type ? msg->network_type : 0;
  const uint32_t major = msg->has_account ? msg->account : 0;
  const uint32_t minor = msg->has_minor ? msg->minor : 0;

  CHECK_PIN

  HDNode* node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  char address[MONERO_ADDRESS_CAPACITY] = {0};
  const bool derived =
      monero_get_address(node->private_key, network, major, minor, address);
  FSM_SCRUB_OBJ(*node);
  if (!derived) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Monero address derivation failed"));
    layoutHome();
    return;
  }

  if (msg->has_show_display && msg->show_display) {
    char description[160] = {0};
    bool described =
        monero_describe(description, sizeof(description), msg->address_n,
                        msg->address_n_count, network);
    if (described && (major || minor)) {
      const size_t used = strlen(description);
      const int n = snprintf(description + used, sizeof(description) - used,
                             "\nSubaddress %lu/%lu", (unsigned long)major,
                             (unsigned long)minor);
      described = n >= 0 && (size_t)n < sizeof(description) - used;
    }
    if (!described) {
      memzero(address, sizeof(address));
      fsm_sendFailure(FailureType_Failure_Other,
                      _("Cannot display Monero address"));
      layoutHome();
      return;
    }
    /* The complete address, paged, then its QR. Never shortened. */
    if (!confirm_address(description, address)) {
      memzero(address, sizeof(address));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Show address cancelled"));
      layoutHome();
      return;
    }
  }

  RESP_INIT(MoneroAddress);
  resp->has_address = true;
  resp->address.size = MONERO_ADDRESS_LENGTH;
  memcpy(resp->address.bytes, address, MONERO_ADDRESS_LENGTH);
  memzero(address, sizeof(address));
  msg_write(MessageType_MessageType_MoneroAddress, resp);
  layoutHome();
}

void fsm_msgMoneroGetWatchKey(const MoneroGetWatchKey* msg) {
  CHECK_INITIALIZED
  if (!monero_check_request(msg->address_n, msg->address_n_count,
                            msg->has_network_type, msg->network_type))
    return;
  const uint32_t network = msg->has_network_type ? msg->network_type : 0;
  const uint32_t major = msg->has_account ? msg->account : 0;
  uint32_t path[3];
  memcpy(path, msg->address_n, sizeof(path));

  CHECK_PIN

  HDNode* node = fsm_getDerivedNode(ED25519_NAME, path, 3, NULL);
  if (!node) return;
  char approved[MONERO_ADDRESS_CAPACITY] = {0};
  const bool ready =
      monero_get_address(node->private_key, network, major, 0, approved);
  FSM_SCRUB_OBJ(*node);
  char description[128] = {0};
  if (!ready ||
      !monero_describe(description, sizeof(description), path, 3, network)) {
    memzero(approved, sizeof(approved));
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Cannot derive Monero wallet"));
    layoutHome();
    return;
  }

  /* Fresh consent on every request: the view key shows every incoming
   * payment of the wallet, now and in the future. */
  if (!confirm(ButtonRequestType_ButtonRequest_Other, _("Export view key"),
               _("%s\nThis computer will see all incoming payments and "
                 "balances of this wallet. It cannot spend."),
               description) ||
      !confirm(ButtonRequestType_ButtonRequest_Address, _("View key for"), "%s",
               approved)) {
    memzero(approved, sizeof(approved));
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Monero view key export cancelled"));
    layoutHome();
    return;
  }

  /* Recheck authorization and rederive after consent, and export only for
   * the wallet whose address was approved. */
  CHECK_PIN
  node = fsm_getDerivedNode(ED25519_NAME, path, 3, NULL);
  if (!node) {
    memzero(approved, sizeof(approved));
    return;
  }
  uint8_t view_key[32] = {0};
  char address[MONERO_ADDRESS_CAPACITY] = {0};
  const bool derived = monero_get_watch_key(node->private_key, network, major,
                                            view_key, address);
  FSM_SCRUB_OBJ(*node);
  const bool same = derived && memcmp(address, approved, sizeof(address)) == 0;
  memzero(approved, sizeof(approved));
  if (!same) {
    FSM_SCRUB(view_key);
    memzero(address, sizeof(address));
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Monero wallet changed during export"));
    layoutHome();
    return;
  }
  RESP_INIT(MoneroWatchKey);
  resp->has_watch_key = true;
  resp->watch_key.size = sizeof(view_key);
  memcpy(resp->watch_key.bytes, view_key, sizeof(view_key));
  resp->has_address = true;
  resp->address.size = MONERO_ADDRESS_LENGTH;
  memcpy(resp->address.bytes, address, MONERO_ADDRESS_LENGTH);
  FSM_SCRUB(view_key);
  memzero(address, sizeof(address));
  msg_write(MessageType_MessageType_MoneroWatchKey, resp);
  /* The encoder has copied the key out; leave no copy in the arena. */
  FSM_SCRUB_OBJ(*resp);
  layoutHome();
}

void fsm_msgMoneroKeyImageExportInit(
    const MoneroKeyImageExportInitRequest* msg) {
  monero_session_abort();
  CHECK_INITIALIZED
  if (!monero_check_request(msg->address_n, msg->address_n_count,
                            msg->has_network_type, msg->network_type))
    return;
  if (!msg->has_num || !msg->num || msg->num > MONERO_KEY_IMAGE_MAX_OUTPUTS ||
      !msg->has_hash || msg->hash.size != 32) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid key-image sync request"));
    layoutHome();
    return;
  }
  const uint32_t network = msg->has_network_type ? msg->network_type : 0;

  CHECK_PIN

  char description[128] = {0};
  if (!monero_describe(description, sizeof(description), msg->address_n,
                       msg->address_n_count, network)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Cannot display Monero request"));
    layoutHome();
    return;
  }
  if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall,
               _("Sync key images"),
               _("%s\nSync key images of %lu outputs? This computer will "
                 "see which of them are spent."),
               description, (unsigned long)msg->num)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Key-image sync cancelled"));
    layoutHome();
    return;
  }
  CHECK_PIN
  HDNode* node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  const bool ok = monero_key_image_begin(node->private_key, msg);
  FSM_SCRUB_OBJ(*node);
  if (!ok) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Cannot start key-image sync"));
    layoutHome();
    return;
  }
  layoutProgress(_("Syncing key images"), 0);
  RESP_INIT(MoneroKeyImageExportInitAck);
  msg_write(MessageType_MessageType_MoneroKeyImageExportInitAck, resp);
}

void fsm_msgMoneroKeyImageSyncStep(const MoneroKeyImageSyncStepRequest* msg) {
  RESP_INIT(MoneroKeyImageSyncStepAck);
  uint32_t permil = 0;
  if (!monero_key_image_step(msg, resp, &permil)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Invalid or unowned key-image output"));
    layoutHome();
    return;
  }
  layoutProgress(_("Syncing key images"), permil);
  msg_write(MessageType_MessageType_MoneroKeyImageSyncStepAck, resp);
}

void fsm_msgMoneroKeyImageSyncFinal(const MoneroKeyImageSyncFinalRequest* msg) {
  (void)msg;
  RESP_INIT(MoneroKeyImageSyncFinalAck);
  if (!monero_key_image_finish(resp->enc_key.bytes)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Key-image count or transcript mismatch"));
    layoutHome();
    return;
  }
  resp->has_enc_key = true;
  resp->enc_key.size = 32;
  msg_write(MessageType_MessageType_MoneroKeyImageSyncFinalAck, resp);
  FSM_SCRUB_OBJ(*resp);
  layoutHome();
}
