#ifndef KEEPKEY_FSM_MONERO_KEY_IMAGE_H
#define KEEPKEY_FSM_MONERO_KEY_IMAGE_H

#include "key-image.h"

void fsm_msgMoneroKeyImageExportInit(MoneroKeyImageExportInitRequest* msg) {
  monero_key_image_abort();
  CHECK_NOT_BTC_ONLY_LOCKED
  CHECK_INITIALIZED
  if (!monero_research_path_valid(msg->address_n, msg->address_n_count) ||
      !msg->has_num || !msg->num || msg->num > MONERO_KEY_IMAGE_MAX_OUTPUTS ||
      !msg->has_hash || msg->hash.size != 32 ||
      (msg->has_network_type && msg->network_type > 2)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid key-image sync initialization");
    layoutHome();
    return;
  }
  CHECK_PIN
  char path[NODE_STRING_LENGTH] = {0};
  if (!bip32_path_to_string(path, sizeof(path), msg->address_n, msg->address_n_count)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid key-image wallet path");
    layoutHome();
    return;
  }
  /* Do not retain a private node throughout the user-confirmation wait. */
  if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, "Sync key images",
               "%s %s\nExport key images for %lu outputs? Reveals which outputs are spent.",
               monero_research_network_name(msg->has_network_type ? msg->network_type : 0),
               path, (unsigned long)msg->num)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Key-image sync cancelled");
    layoutHome();
    return;
  }
  HDNode* node = fsm_getDerivedNode("ed25519", msg->address_n, msg->address_n_count, NULL);
  if (!node) return;
  bool ok = monero_key_image_begin(node->private_key, msg);
  FSM_SCRUB_OBJ(*node);
  if (!ok) {
    monero_key_image_abort();
    fsm_sendFailure(FailureType_Failure_Other, "Cannot initialize key-image sync");
    layoutHome();
    return;
  }
  RESP_INIT(MoneroKeyImageExportInitAck);
  msg_write(MessageType_MessageType_MoneroKeyImageExportInitAck, resp);
  layoutHome();
}

void fsm_msgMoneroKeyImageSyncStep(MoneroKeyImageSyncStepRequest* msg) {
  RESP_INIT(MoneroKeyImageSyncStepAck);
  if (!monero_key_image_step(msg, resp)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid or unowned key-image output");
    layoutHome();
    return;
  }
  msg_write(MessageType_MessageType_MoneroKeyImageSyncStepAck, resp);
}

void fsm_msgMoneroKeyImageSyncFinal(MoneroKeyImageSyncFinalRequest* msg) {
  (void)msg;
  RESP_INIT(MoneroKeyImageSyncFinalAck);
  if (!monero_key_image_finish(resp->enc_key.bytes)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, "Key-image count or transcript mismatch");
    layoutHome();
    return;
  }
  resp->has_enc_key = true;
  resp->enc_key.size = 32;
  msg_write(MessageType_MessageType_MoneroKeyImageSyncFinalAck, resp);
  memzero(resp, sizeof(*resp));
  layoutHome();
}

#endif
