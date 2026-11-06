#ifndef KEEPKEY_FSM_MSG_MONERO_RESEARCH_H
#define KEEPKEY_FSM_MSG_MONERO_RESEARCH_H

/* Textually included in fsm.c after the ordinary storage/PIN/derivation
 * helpers, only in the explicitly selected regular-emulator research build. */
#include "monero_research.h"

void fsm_msgMoneroGetAddress(MoneroGetAddress* msg) {
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
  /* Integrated addresses are intentionally outside this address-only stage.
   * Reject presence even when empty so clients cannot assume it was honored. */
  if (msg->has_payment_id) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Monero integrated addresses are not implemented");
    layoutHome();
    return;
  }

  CHECK_PIN

  HDNode* node = fsm_getDerivedNode("ed25519", msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  const uint32_t major = msg->has_account ? msg->account : 0;
  const uint32_t minor = msg->has_minor ? msg->minor : 0;
  char address[MONERO_RESEARCH_ADDRESS_CAPACITY] = {0};
  const bool derived = monero_research_get_address(node->private_key, network,
                                                   major, minor, address);
  /* No private node remains live during a host/button confirmation wait. */
  FSM_SCRUB_OBJ(*node);
  if (!derived) {
    fsm_sendFailure(FailureType_Failure_Other, "Monero address derivation failed");
    memzero(address, sizeof(address));
    layoutHome();
    return;
  }

  if (msg->has_show_display && msg->show_display) {
    char path[NODE_STRING_LENGTH] = {0};
    char description[160] = {0};
    if (!bip32_path_to_string(path, sizeof(path), msg->address_n,
                               msg->address_n_count)) {
      fsm_sendFailure(FailureType_Failure_Other, "Cannot display Monero path");
      memzero(address, sizeof(address));
      layoutHome();
      return;
    }
    int written = snprintf(description, sizeof(description),
        "Monero %s\n%s\nSubaddress %lu/%lu",
        monero_research_network_name(network), path,
        (unsigned long)major, (unsigned long)minor);
    if (written < 0 || (size_t)written >= sizeof(description)) {
      fsm_sendFailure(FailureType_Failure_Other, "Cannot display Monero request");
      memzero(address, sizeof(address));
      layoutHome();
      return;
    }
    /* The generic address flow paginates the complete path/network/indices,
     * complete 95-character address, and QR. No truncated address approval. */
    if (!confirm_address(description, address)) {
      memzero(address, sizeof(address));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Show Monero address cancelled");
      layoutHome();
      return;
    }
  }

  RESP_INIT(MoneroAddress);
  resp->has_address = true;
  resp->address.size = MONERO_RESEARCH_ADDRESS_LENGTH;
  memcpy(resp->address.bytes, address, MONERO_RESEARCH_ADDRESS_LENGTH);
  memzero(address, sizeof(address));
  msg_write(MessageType_MessageType_MoneroAddress, resp);
  layoutHome();
}

#endif
