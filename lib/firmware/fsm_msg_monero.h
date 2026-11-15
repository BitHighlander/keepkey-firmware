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

/* ---------------------------------------------------------------------
 * Streamed transaction signing (1810-1825). The engine is monero_tx.c;
 * these handlers add the review, the progress display, the shared-arena
 * wiring and the wire replies.
 *
 * FRAME ARENA. The range proof and each CLSAG need 5-7 KB of scratch, lent
 * from frame_arena (lib/board/messages.c) through frame_arena_scratch().
 * It is idle for exactly as long as it is lent:
 *  - The request is already out of it: usb_rx_helper() reassembles into
 *    frame_arena.rx and dispatch() decodes that into decode_buffer before it
 *    calls the handler.
 *  - Nothing is encoded into it until the handler replies: msg_write() and
 *    msg_debug_write() are the only frame_arena_tx() callers (lib/board/
 *    usb.c), and the handler makes no confirm, ButtonRequest or reply while
 *    the scratch is live. The whole review happens in TxInit, which uses no
 *    scratch.
 *  - No new frame lands in it while the handler computes: usbPoll() runs
 *    only where it is called (no USB interrupt), and the one place a proving
 *    step calls it is check_for_tiny_msg(), where handle_usb_rx() and
 *    handle_debug_usb_rx() route every packet to msg_read_tiny() and its own
 *    64-byte buffer.
 *  - A tiny packet that is refused does touch the arena:
 *    msg_reject_short_tiny_packet() resets it and reject_tiny_message()
 *    answers through msg_write(). Both set msg_handler_rejected().
 * So monero_proving_step() below ends the proof the moment a poll reports
 * anything at all, or a rejection: the prover then returns without reading
 * or writing the scratch again (monero/crypto.h, ABORT CONTRACT), the engine
 * ends and wipes the session, and the handler wipes the arena. A message in
 * the middle of a proof therefore always ends the whole signing session;
 * nothing half-done survives. */

#include "keepkey/firmware/monero_tx.h"

static void monero_tx_fail(MoneroTxResult result) {
  FailureType code = FailureType_Failure_SyntaxError;
  if (result == MONERO_TX_ERR_STEP || result == MONERO_TX_ERR_EXPIRED)
    code = FailureType_Failure_UnexpectedMessage;
  else if (result >= MONERO_TX_ERR_NOT_OWNED)
    code = FailureType_Failure_Other;
  fsm_sendFailure(code, monero_tx_result_text(result));
  layoutHome();
}

/* "1.234567890123 XMR": all 12 decimals, never rounded. */
static bool monero_format_amount(uint64_t amount, char* out, size_t size) {
  return bn_format_uint64(amount, NULL, " XMR", 12, 0, true, out, size) != 0;
}

/* Every screen names a network other than mainnet. */
static const char* monero_tx_title(uint32_t network, const char* mainnet,
                                   const char* testnet, const char* stagenet) {
  return network == MoneroNetworkType_MONERO_NETWORK_TESTNET    ? testnet
         : network == MoneroNetworkType_MONERO_NETWORK_STAGENET ? stagenet
                                                                : mainnet;
}

/* The one review of the whole transaction, before any signing step: the
 * recipient with its complete address, the payment ID, the change (shown as
 * change only because the device classified it), any lock, then the fee and
 * the total. Everything shown was derived or re-encoded on the device. */
static bool monero_tx_confirm(const MoneroTxReview* review) {
  char amount[40] = {0}, total[40] = {0};
  for (unsigned j = 0; j < MONERO_TX_OUTPUTS; ++j) {
    const MoneroTxReviewOutput* out = &review->outputs[j];
    if (!monero_format_amount(out->amount, amount, sizeof(amount)))
      return false;
    if (out->is_change) {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   monero_tx_title(review->network, _("Monero change"),
                                   _("Monero TESTNET change"),
                                   _("Monero STAGENET change")),
                   _("Change %s returns to this wallet (account %lu), to "
                     "your address\n%s"),
                   amount, (unsigned long)review->account, out->address))
        return false;
      continue;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 monero_tx_title(review->network, _("Monero send"),
                                 _("Monero TESTNET send"),
                                 _("Monero STAGENET send")),
                 _("Send %s to %s\n%s"), amount,
                 out->is_integrated   ? _("integrated address")
                 : out->is_subaddress ? _("subaddress")
                                      : _("standard address"),
                 out->address))
      return false;
    if (out->is_integrated) {
      char payment_id[17] = {0};
      data2hex(review->payment_id, 8, payment_id);
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   monero_tx_title(review->network, _("Monero payment ID"),
                                   _("Monero TESTNET payment ID"),
                                   _("Monero STAGENET payment ID")),
                   _("Payment ID %s is sent with this payment."), payment_id))
        return false;
    }
  }
  if (review->unlock_time) {
    /* Unusual, but the user's to decide: shown, then signed. */
    char unlock[24] = {0};
    if (!bn_format_uint64(review->unlock_time, NULL, NULL, 0, 0, false, unlock,
                          sizeof(unlock)) ||
        !confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 monero_tx_title(review->network, _("Monero WARNING"),
                                 _("Monero TESTNET WARNING"),
                                 _("Monero STAGENET WARNING")),
                 _("These funds are locked: nobody can spend them before "
                   "block or time %s."),
                 unlock))
      return false;
  }
  if (!monero_format_amount(review->fee, amount, sizeof(amount)) ||
      !monero_format_amount(review->total, total, sizeof(total)))
    return false;
  return confirm(
      ButtonRequestType_ButtonRequest_SignTx,
      monero_tx_title(review->network, _("Sign Monero"),
                      _("Sign Monero TESTNET"), _("Sign Monero STAGENET")),
      _("Fee %s\nTotal %s\n%lu input(s), ring size 16. Signing "
        "takes about 20 seconds."),
      amount, total, (unsigned long)review->num_inputs);
}

/* Progress, in thousandths of the whole session: inputs 0-50, their order
 * 50-60, the first output 70, the range proof 70-850, each CLSAG a share of
 * 850-990. */
static void monero_tx_show_progress(const char* text, uint32_t permil) {
  note_workflow_progress();
  layoutProgress(text, (int)permil);
}

typedef struct {
  const char* text;
  uint32_t base, span, last;
  bool interrupted;
} MoneroProving;

/* The crypto module's progress callback: redraw, and poll the host. Any
 * message at all ends the proof (see FRAME ARENA above). */
static bool monero_proving_step(void* context, uint32_t done, uint32_t total) {
  MoneroProving* proving = (MoneroProving*)context;
  uint8_t tiny[MSG_TINY_BFR_SZ];
  const MessageType message = check_for_tiny_msg(tiny);
  memzero(tiny, sizeof(tiny));
  if (message != MSG_TINY_TYPE_ERROR || msg_handler_rejected()) {
    if (message == MessageType_MessageType_Initialize) reset_msg_stack = true;
    proving->interrupted = true;
    return false;
  }
  const uint32_t permil =
      proving->base + (total ? proving->span * done / total : 0);
  if (permil != proving->last) {
    proving->last = permil;
    layoutProgress(proving->text, (int)permil);
  }
  return true;
}

/* After a proving step that failed: the session is already gone. */
static void monero_tx_fail_proving(MoneroTxResult result,
                                   const MoneroProving* proving) {
  frame_arena_scratch_wipe();
  if (proving->interrupted) {
    /* A refused packet was already answered; fsm_sendFailure then stays
     * silent. Otherwise this is the host's Cancel or Initialize. */
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Monero signing cancelled"));
    layoutHome();
    return;
  }
  monero_tx_fail(result);
}

void fsm_msgMoneroTxInit(const MoneroTxInitRequest* msg) {
  monero_session_abort();
  CHECK_INITIALIZED
  if (!monero_check_request(msg->address_n, msg->address_n_count,
                            msg->has_network_type, msg->network_type))
    return;

  CHECK_PIN

  HDNode* node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  /* Public data only: nothing secret is held across the review. */
  MoneroTxReview review;
  MoneroTxResult result = monero_tx_review(node->private_key, msg, &review);
  FSM_SCRUB_OBJ(*node);
  if (result != MONERO_TX_OK) {
    monero_tx_fail(result);
    return;
  }
  if (!monero_tx_confirm(&review)) {
    memzero(&review, sizeof(review));
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Monero signing cancelled"));
    layoutHome();
    return;
  }

  /* Recheck authorization and rederive after consent; the session opens
   * only for the plan whose digest was just approved. */
  uint8_t approved[32];
  memcpy(approved, review.digest, sizeof(approved));
  memzero(&review, sizeof(review));
  CHECK_PIN
  node = fsm_getDerivedNode(ED25519_NAME, msg->address_n, msg->address_n_count,
                            NULL);
  if (!node) return;
  RESP_INIT(MoneroTxInitAck);
  result = monero_tx_begin(node->private_key, msg, approved, resp);
  FSM_SCRUB_OBJ(*node);
  if (result != MONERO_TX_OK) {
    monero_tx_fail(result);
    return;
  }
  monero_tx_show_progress(_("Signing Monero"), 0);
  msg_write(MessageType_MessageType_MoneroTxInitAck, resp);
}

void fsm_msgMoneroTxSetInput(const MoneroTxSetInputRequest* msg) {
  RESP_INIT(MoneroTxSetInputAck);
  const MoneroTxResult result = monero_tx_set_input(msg, resp);
  if (result != MONERO_TX_OK) {
    monero_tx_fail(result);
    return;
  }
  monero_tx_show_progress(_("Signing Monero"), 25);
  msg_write(MessageType_MessageType_MoneroTxSetInputAck, resp);
}

void fsm_msgMoneroTxInputVini(const MoneroTxInputViniRequest* msg) {
  const MoneroTxResult result = monero_tx_input_vini(msg);
  if (result != MONERO_TX_OK) {
    monero_tx_fail(result);
    return;
  }
  monero_tx_show_progress(_("Signing Monero"), 50);
  RESP_INIT(MoneroTxInputViniAck);
  msg_write(MessageType_MessageType_MoneroTxInputViniAck, resp);
}

void fsm_msgMoneroTxAllInputsSet(const MoneroTxAllInputsSetRequest* msg) {
  (void)msg;
  const MoneroTxResult result = monero_tx_all_inputs_set();
  if (result != MONERO_TX_OK) {
    monero_tx_fail(result);
    return;
  }
  monero_tx_show_progress(_("Signing Monero"), 60);
  RESP_INIT(MoneroTxAllInputsSetAck);
  msg_write(MessageType_MessageType_MoneroTxAllInputsSetAck, resp);
}

void fsm_msgMoneroTxSetOutput(const MoneroTxSetOutputRequest* msg) {
  MoneroProving proving = {_("Monero: range proof"), 70, 780, 0, false};
  void* scratch = NULL;
  if (monero_tx_next_output_proves()) {
    scratch = frame_arena_scratch(MONERO_TX_BPP_SCRATCH_BYTES);
    layoutProgress(proving.text, (int)proving.base);
  }
  RESP_INIT(MoneroTxSetOutputAck);
  const MoneroTxResult result =
      monero_tx_set_output(msg, resp, scratch, MONERO_TX_BPP_SCRATCH_BYTES,
                           monero_proving_step, &proving);
  if (result != MONERO_TX_OK) {
    monero_tx_fail_proving(result, &proving);
    return;
  }
  if (scratch) frame_arena_scratch_wipe();
  monero_tx_show_progress(_("Signing Monero"), scratch ? 850 : 70);
  msg_write(MessageType_MessageType_MoneroTxSetOutputAck, resp);
}

void fsm_msgMoneroTxAllOutSet(const MoneroTxAllOutSetRequest* msg) {
  (void)msg;
  RESP_INIT(MoneroTxAllOutSetAck);
  const MoneroTxResult result = monero_tx_all_out_set(resp);
  if (result != MONERO_TX_OK) {
    monero_tx_fail(result);
    return;
  }
  monero_tx_show_progress(_("Signing Monero"), 850);
  msg_write(MessageType_MessageType_MoneroTxAllOutSetAck, resp);
}

void fsm_msgMoneroTxSignInput(const MoneroTxSignInputRequest* msg) {
  uint32_t inputs = 1, position = 0;
  char text[40] = "Signing Monero";
  if (monero_tx_progress(&inputs, &position) && inputs)
    snprintf(text, sizeof(text), _("Monero: signing input %lu/%lu"),
             (unsigned long)(position + 1), (unsigned long)inputs);
  else
    inputs = 1;
  MoneroProving proving = {text, 850 + 140 * position / inputs, 140 / inputs, 0,
                           false};
  void* scratch = frame_arena_scratch(MONERO_TX_CLSAG_SCRATCH_BYTES);
  RESP_INIT(MoneroTxSignInputAck);
  const MoneroTxResult result =
      monero_tx_sign_input(msg, resp, scratch, MONERO_TX_CLSAG_SCRATCH_BYTES,
                           monero_proving_step, &proving);
  if (result != MONERO_TX_OK) {
    monero_tx_fail_proving(result, &proving);
    return;
  }
  frame_arena_scratch_wipe();
  monero_tx_show_progress(text, 850 + 140 * (position + 1) / inputs);
  msg_write(MessageType_MessageType_MoneroTxSignInputAck, resp);
  /* The encoder has copied the sealed signature out. */
  FSM_SCRUB_OBJ(*resp);
}

void fsm_msgMoneroTxFinal(const MoneroTxFinalRequest* msg) {
  (void)msg;
  RESP_INIT(MoneroTxFinalAck);
  const MoneroTxResult result = monero_tx_final(resp);
  if (result != MONERO_TX_OK) {
    monero_tx_fail(result);
    return;
  }
  msg_write(MessageType_MessageType_MoneroTxFinalAck, resp);
  FSM_SCRUB_OBJ(*resp);
  layoutHome();
}
