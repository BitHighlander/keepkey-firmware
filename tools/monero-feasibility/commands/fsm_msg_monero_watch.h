#ifndef KEEPKEY_FSM_MSG_MONERO_WATCH_H
#define KEEPKEY_FSM_MSG_MONERO_WATCH_H

#include "watch-key.h"

void fsm_msgMoneroGetWatchKey(MoneroGetWatchKey* msg) {
  CHECK_NOT_BTC_ONLY_LOCKED
  CHECK_INITIALIZED
  if (!monero_research_path_valid(msg->address_n, msg->address_n_count)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Expected Monero path m/44'/128'/account'");
    layoutHome();
    return;
  }
  const uint32_t network = msg->has_network_type ? msg->network_type : 0;
  if (!monero_research_network_name(network)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid Monero network");
    layoutHome();
    return;
  }
  uint32_t path[3];
  memcpy(path, msg->address_n, sizeof(path));
  CHECK_PIN
  HDNode* node = fsm_getDerivedNode("ed25519", path, 3, NULL);
  if (!node) return;
  char approved_address[MONERO_RESEARCH_ADDRESS_CAPACITY] = {0};
  const bool ready = monero_research_get_address(node->private_key, network,
                                                  0, 0, approved_address);
  FSM_SCRUB_OBJ(*node);
  if (!ready) {
    fsm_sendFailure(FailureType_Failure_Other, "Cannot derive Monero wallet");
    layoutHome();
    return;
  }
  char path_text[NODE_STRING_LENGTH] = {0};
  char description[128] = {0};
  if (!bip32_path_to_string(path_text, sizeof(path_text), path, 3)) {
    fsm_sendFailure(FailureType_Failure_Other, "Cannot display Monero path");
    layoutHome();
    return;
  }
  int size = snprintf(description, sizeof(description),
      "Monero %s\n%s\nExport view key", monero_research_network_name(network),
      path_text);
  if (size < 0 || (size_t)size >= sizeof(description)) {
    fsm_sendFailure(FailureType_Failure_Other, "Cannot display Monero export");
    layoutHome();
    return;
  }
  /* No private view key or derived node is held across these blocking waits. */
  if (!confirm(ButtonRequestType_ButtonRequest_Other, "Export view key",
               "Allow this computer to scan incoming Monero transactions? "
               "The private view key cannot spend funds.") ||
      !confirm_address(description, approved_address)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Monero view-key export cancelled");
    layoutHome();
    return;
  }
  /* Recheck authorization and rederive after consent. Bind export to the
   * wallet address that was approved, even if a session were to change. */
  CHECK_PIN
  node = fsm_getDerivedNode("ed25519", path, 3, NULL);
  if (!node) return;
  uint8_t watch_key[32] = {0};
  char address[MONERO_RESEARCH_ADDRESS_CAPACITY] = {0};
  bool derived = monero_research_get_watch_key(node->private_key, network,
                                               watch_key, address);
  FSM_SCRUB_OBJ(*node);
  if (!derived || memcmp(address, approved_address, sizeof(address))) {
    FSM_SCRUB(watch_key);
    memzero(address, sizeof(address));
    fsm_sendFailure(FailureType_Failure_Other,
                    "Monero wallet changed during export authorization");
    layoutHome();
    return;
  }
  RESP_INIT(MoneroWatchKey);
  resp->has_watch_key = true;
  resp->watch_key.size = sizeof(watch_key);
  memcpy(resp->watch_key.bytes, watch_key, sizeof(watch_key));
  resp->has_address = true;
  resp->address.size = MONERO_RESEARCH_ADDRESS_LENGTH;
  memcpy(resp->address.bytes, address, MONERO_RESEARCH_ADDRESS_LENGTH);
  FSM_SCRUB(watch_key);
  memzero(address, sizeof(address));
  msg_write(MessageType_MessageType_MoneroWatchKey, resp);
  /* The encoder has copied the explicitly authorized bytes into the output
   * transport; do not leave another copy in the shared response arena. */
  FSM_SCRUB_OBJ(*resp);
  layoutHome();
}

#endif
