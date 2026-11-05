#ifndef KEEPKEY_FSM_MSG_MONERO_SIGN_H
#define KEEPKEY_FSM_MSG_MONERO_SIGN_H

#include "signing-plan.h"

typedef struct {
  bool active;
  uint32_t path[3];
  monero_core_plan plan;
  monero_core_summary approved;
  monero_core_summary current;
  uint8_t transaction[MONERO_CORE_MAX_TX_BYTES];
  size_t transaction_size;
  uint8_t transaction_hash[32];
  char error[MONERO_CORE_ERROR_CAPACITY];
} MoneroSigningContext;

static MoneroSigningContext CONFIDENTIAL monero_signing_context;

bool monero_signing_active(void) { return monero_signing_context.active; }
void monero_signing_abort(void) {
  memzero(&monero_signing_context, sizeof(monero_signing_context));
}
bool monero_signing_state_is_zero(void) {
  const uint8_t* bytes = (const uint8_t*)&monero_signing_context;
  uint8_t aggregate = 0;
  for (size_t i = 0; i < sizeof(monero_signing_context); ++i) aggregate |= bytes[i];
  return aggregate == 0;
}

static bool monero_signing_output_review(const monero_core_destination* output,
                                          size_t index, size_t count,
                                          uint32_t network) {
  /* Copies are public and remain stable even if authorization revocation
   * clears the context while a confirmation is parked. */
  char address[96] = {0}, amount[40] = {0}, description[192] = {0};
  memcpy(address, output->address, sizeof(address));
  if (!monero_signing_format_amount(output->amount, amount, sizeof(amount))) return false;
  int written = snprintf(description, sizeof(description),
      "Monero %s\nOutput %lu/%lu: %s\nAmount %s",
      monero_research_network_name(network), (unsigned long)index + 1,
      (unsigned long)count, output->is_change ? "Change" : "Recipient", amount);
  if (written < 0 || (size_t)written >= sizeof(description)) return false;
  if (output->is_change) {
    size_t used = (size_t)written;
    written = snprintf(description + used, sizeof(description) - used,
        "\nChange subaddress %lu/%lu", (unsigned long)output->change_major,
        (unsigned long)output->change_minor);
    if (written < 0 || (size_t)written >= sizeof(description) - used) return false;
  }
  /* Same full-text/QR components as confirm_address, with an authorization
   * check between every field so a revoked context cannot advance review. */
  return confirm(ButtonRequestType_ButtonRequest_SignTx, "Output details", "%s", description) &&
         monero_signing_active() &&
         confirm(ButtonRequestType_ButtonRequest_Address, "Output address", "%s", address) &&
         monero_signing_active() &&
         confirm_qr("Output QR", address) && monero_signing_active();
}

void fsm_msgMoneroResearchSignTransaction(MoneroResearchSignTransaction* msg) {
  monero_signing_abort();
  CHECK_NOT_BTC_ONLY_LOCKED
  CHECK_INITIALIZED
  MoneroSigningContext* context = &monero_signing_context;
  HDNode* node = NULL;
  bool send_failure = false;
  FailureType failure_code = FailureType_Failure_Other;
  char failure_text[MONERO_CORE_ERROR_CAPACITY] = {0};
  uint32_t requested_path[3] = {0};
  if (!monero_signing_plan_from_message(msg, &context->plan, context->error)) {
    failure_code = FailureType_Failure_SyntaxError;
    send_failure = true;
    snprintf(failure_text, sizeof(failure_text), "%s", context->error);
    goto cleanup;
  }
  memcpy(requested_path, msg->address_n, sizeof(requested_path));
  /* PIN/passphrase processing may call session_clear(), which revokes every
   * signing context. Retain no plan there; recopy only after authentication. */
  monero_signing_abort();
  if (!pin_protect_cached()) goto cleanup;
  node = fsm_getDerivedNode("ed25519", requested_path, 3, NULL);
  if (!node) goto cleanup;
  if (!monero_signing_plan_from_message(msg, &context->plan, context->error)) {
    failure_code = FailureType_Failure_SyntaxError;
    send_failure = true;
    snprintf(failure_text, sizeof(failure_text), "%s", context->error);
    goto cleanup;
  }
  if (memcmp(requested_path, msg->address_n, sizeof(requested_path))) {
    send_failure = true;
    snprintf(failure_text, sizeof(failure_text), "Monero wallet path changed during authentication");
    goto cleanup;
  }
  memcpy(context->path, requested_path, sizeof(context->path));
  bool validated = monero_core_validate(&context->plan, node->private_key,
                                          &context->approved, context->error) != 0;
  FSM_SCRUB_OBJ(*node);
  node = NULL;
  context->error[sizeof(context->error)-1] = '\0';
  if (!validated) {
    send_failure = true;
    snprintf(failure_text, sizeof(failure_text), "%s", context->error[0] ? context->error : "Invalid Monero transaction");
    goto cleanup;
  }
  if (!monero_signing_summary_matches_plan(&context->plan, &context->approved) ||
      !monero_signing_summary_matches(&context->approved, &context->approved)) {
    send_failure = true;
    snprintf(failure_text, sizeof(failure_text), "Invalid Monero transaction summary");
    goto cleanup;
  }
  context->active = true;
  {
    char path_text[NODE_STRING_LENGTH] = {0}, fee[40] = {0};
    if (!bip32_path_to_string(path_text, sizeof(path_text), context->path, 3) ||
        !monero_signing_format_amount(context->approved.fee, fee, sizeof(fee))) {
      send_failure = true;
      snprintf(failure_text, sizeof(failure_text), "Cannot display Monero transaction");
      goto cleanup;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Monero transaction",
                 "%s\n%s\n%lu inputs, %lu outputs\nFee %s",
                 monero_research_network_name(context->plan.network), path_text,
                 (unsigned long)context->plan.input_count,
                 (unsigned long)context->approved.output_count, fee) ||
        !monero_signing_active()) goto cancelled;
    for (size_t i = 0; i < context->approved.output_count; ++i) {
      if (!monero_signing_output_review(&context->approved.destinations[i], i,
                                          context->approved.output_count,
                                          context->plan.network)) goto cancelled;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Sign Monero tx",
                 "All %lu outputs reviewed.\nFee %s\nSign this transaction?",
                 (unsigned long)context->approved.output_count, fee) ||
        !monero_signing_active()) goto cancelled;
  }
  if (!pin_protect_cached()) goto cleanup;
  if (!monero_signing_active()) goto cancelled;
  node = fsm_getDerivedNode("ed25519", context->path, 3, NULL);
  if (!node) goto cleanup;
  if (!monero_signing_active()) goto cancelled;
  validated = monero_core_validate(&context->plan, node->private_key,
                                      &context->current, context->error) != 0;
  context->error[sizeof(context->error)-1] = '\0';
  if (!validated || !monero_signing_summary_matches_plan(&context->plan, &context->current) ||
      !monero_signing_summary_matches(&context->approved, &context->current)) {
    send_failure = true;
    snprintf(failure_text, sizeof(failure_text), "Monero wallet or transaction changed after review");
    goto cleanup;
  }
  bool signed_ok = monero_core_sign(&context->plan, node->private_key,
      context->transaction, sizeof(context->transaction), &context->transaction_size,
      context->transaction_hash, context->error) != 0;
  FSM_SCRUB_OBJ(*node);
  node = NULL;
  if (!monero_signing_active()) goto cancelled;
  context->error[sizeof(context->error)-1] = '\0';
  bool verified = false;
  if (signed_ok && context->transaction_size &&
      context->transaction_size <= sizeof(context->transaction)) {
    verified = monero_core_verify(&context->plan, context->transaction,
                                   context->transaction_size, context->error) != 0;
  }
  context->error[sizeof(context->error)-1] = '\0';
  if (!signed_ok || !verified) {
    send_failure = true;
    snprintf(failure_text, sizeof(failure_text), "%s", context->error[0] ? context->error : "Monero transaction verification failed");
    goto cleanup;
  }
  if (!monero_signing_active()) goto cancelled;
  {
    RESP_INIT(MoneroResearchSignedTransaction);
    resp->tx_blob.size = context->transaction_size;
    memcpy(resp->tx_blob.bytes, context->transaction, context->transaction_size);
    resp->tx_hash.size = sizeof(context->transaction_hash);
    memcpy(resp->tx_hash.bytes, context->transaction_hash, sizeof(context->transaction_hash));
    msg_write(MessageType_MessageType_MoneroResearchSignedTransaction, resp);
    FSM_SCRUB_OBJ(*resp);
  }
  goto cleanup;
cancelled:
  send_failure = true;
  failure_code = FailureType_Failure_ActionCancelled;
  snprintf(failure_text, sizeof(failure_text), "Monero transaction signing cancelled");
cleanup:
  if (node) FSM_SCRUB_OBJ(*node);
  monero_signing_abort();
  if (send_failure) fsm_sendFailure(failure_code, failure_text);
  memzero(failure_text, sizeof(failure_text));
  layoutHome();
}

#endif
