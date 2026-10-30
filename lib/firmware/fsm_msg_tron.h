/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2024 KeepKey
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

void fsm_msgTronGetAddress(const TronGetAddress* msg) {
  RESP_INIT(TronAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  // Validate path: m/44'/195'/...
  if (msg->address_n_count < 3 || msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 195)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TRON path (expected m/44'/195'/...)"));
    layoutHome();
    return;
  }

  // Derive node using secp256k1 curve
  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  // Get TRON address from public key (Base58Check with prefix 'T')
  char address[MAX_ADDR_SIZE];
  if (!tron_getAddress(node->public_key, address, sizeof(address))) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("Address derivation failed"));
    layoutHome();
    return;
  }

  resp->has_address = true;
  strlcpy(resp->address, address, sizeof(resp->address));

  // Show address on display if requested
  if (msg->has_show_display && msg->show_display) {
    char node_str[NODE_STRING_LENGTH];
    if (!bip32_path_to_string(node_str, sizeof(node_str), msg->address_n,
                              msg->address_n_count)) {
      memset(node_str, 0, sizeof(node_str));
    }

    if (!confirm_ethereum_address(node_str, resp->address)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Show address cancelled"));
      layoutHome();
      return;
    }
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_TronAddress, resp);
  layoutHome();
}

static const char* tron_resourceName(uint8_t resource) {
  return resource == TRON_RESOURCE_ENERGY       ? "ENERGY"
         : resource == TRON_RESOURCE_TRON_POWER ? "TRON POWER"
                                                : "BANDWIDTH";
}

static bool tron_confirmVotes(const TronParsedTx* p) {
  const unsigned n = p->vote_count;
  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "TRON Vote",
               "Vote for %u SR%s? This replaces all your current votes.", n,
               n == 1 ? "" : "s"))
    return false;
  for (uint8_t i = 0; i < p->vote_count; i++) {
    uint8_t sr[TRON_RAW_ADDRESS_SIZE];
    uint64_t count;
    bignum256 val;
    char count_str[24];
    char sr_str[TRON_ADDRESS_MAX_LEN];
    char title[16];
    if (!tron_voteAt(p, i, sr, &count) ||
        !tron_addressFromBytes(sr, sr_str, sizeof(sr_str)))
      return false;
    bn_read_uint64(count, &val);
    if (!bn_format(&val, NULL, NULL, 0, 0, false, count_str, sizeof(count_str)))
      return false;
    snprintf(title, sizeof(title), "Vote %u/%u", (unsigned)i + 1, n);
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                 "%s votes for %s", count_str, sr_str))
      return false;
  }
  return true;
}

/* The review screens of a parsed transaction. Every value shown comes from
 * raw_data; token is the trusted table entry of a TRC-20 call, or NULL. */
static bool tron_confirmParsed(const TronParsedTx* p, const TronToken* token) {
  char amount_str[96];
  char to_str[TRON_ADDRESS_MAX_LEN];
  switch (p->type) {
    case TRON_TX_TRANSFER:
      tron_formatAmount(amount_str, sizeof(amount_str), p->amount);
      return tron_addressFromBytes(p->to, to_str, sizeof(to_str)) &&
             confirm(ButtonRequestType_ButtonRequest_SignTx, "TRON",
                     "Send %s to %s?", amount_str, to_str);
    case TRON_TX_FREEZE_V2:
      tron_formatAmount(amount_str, sizeof(amount_str), p->amount);
      return confirm(ButtonRequestType_ButtonRequest_SignTx, "TRON Stake",
                     "Stake %s for %s?", amount_str,
                     tron_resourceName(p->resource));
    case TRON_TX_UNFREEZE_V2:
      tron_formatAmount(amount_str, sizeof(amount_str), p->amount);
      return confirm(ButtonRequestType_ButtonRequest_SignTx, "TRON Unstake",
                     "Unstake %s from %s?", amount_str,
                     tron_resourceName(p->resource));
    case TRON_TX_VOTE_WITNESS:
      return tron_confirmVotes(p);
    default: /* TRC-20 transfer() or approve() */
      break;
  }

  const bool approve = p->type == TRON_TX_TRC20_APPROVE;
  const char* title = approve ? "TRC-20 Approve" : "TRC-20 Transfer";
  if (!tron_addressFromBytes(p->to, to_str, sizeof(to_str))) return false;
  if (!token) { /* blind-signed: name the contract, amounts in base units */
    char contract_str[TRON_ADDRESS_MAX_LEN];
    if (!tron_addressFromBytes(p->contract, contract_str,
                               sizeof(contract_str)) ||
        !confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                 "Token contract %s", contract_str))
      return false;
  }
  const char* asset = token ? token->symbol : "tokens";
  if (approve && ethereum_allowanceAmountIsUnlimited(p->trc20_amount)) {
    return confirm(ButtonRequestType_ButtonRequest_SignTx, "UNLIMITED approval",
                   "Allow %s to spend ALL your %s?", to_str, asset);
  }
  bool zero = true;
  for (int i = 0; i < 32; i++) zero = zero && p->trc20_amount[i] == 0;
  if (approve && zero) {
    return confirm(ButtonRequestType_ButtonRequest_SignTx, title,
                   "Remove approval for %s to spend your %s?", to_str, asset);
  }
  if (!tron_formatTrc20Amount(p->trc20_amount, token, amount_str,
                              sizeof(amount_str)))
    return false;
  const char* units = token ? "" : " base units";
  return approve ? confirm(ButtonRequestType_ButtonRequest_SignTx, title,
                           "Allow %s to spend up to %s%s?", to_str, amount_str,
                           units)
                 : confirm(ButtonRequestType_ButtonRequest_SignTx, title,
                           "Send %s%s to %s?", amount_str, units, to_str);
}

// cppcheck-suppress constParameterPointer -- protobuf dispatcher ABI is mutable
void fsm_msgTronSignTx(TronSignTx* msg) {
  RESP_INIT(TronSignedTx);

  CHECK_INITIALIZED

  CHECK_PIN

  // Validate path: m/44'/195'/...
  if (msg->address_n_count < 3 || msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 195)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TRON path (expected m/44'/195'/...)"));
    layoutHome();
    return;
  }

  // Derive node using secp256k1 curve
  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  if (!msg->has_raw_data || msg->raw_data.size == 0) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("Missing transaction data"));
    layoutHome();
    return;
  }

  /* Clear-sign from raw_data itself — the exact bytes being signed.
   * (The proto's side-channel to_address/amount fields are never trusted:
   * they are not part of what is signed.) */
  TronParsedTx parsed;
  TronTxType tx_type =
      tron_parseRawTx(msg->raw_data.bytes, msg->raw_data.size, &parsed);

  /* Unrecognized payloads are explicit blind-sign only, as for Solana. So is
   * a TRC-20 call to a contract outside the trusted table: the transfer or
   * approve selector alone does not prove what that contract executes. Its
   * decoded fields follow the warning. */
  const bool trc20 =
      tx_type == TRON_TX_TRC20_TRANSFER || tx_type == TRON_TX_TRC20_APPROVE;
  const TronToken* token = trc20 ? tron_knownToken(parsed.contract) : NULL;
  if (tx_type == TRON_TX_UNVERIFIED || (trc20 && !token)) {
    if (!storage_isPolicyEnabled("AdvancedMode")) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_Other,
                      _("Enable AdvancedMode to blind-sign"));
      layoutHome();
      return;
    }
    char blind_msg[48];
    snprintf(blind_msg, sizeof(blind_msg), "Sign %u-byte TRON transaction?",
             (unsigned)msg->raw_data.size);
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "TRON Blind Sign",
                 "%s", blind_msg)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
      layoutHome();
      return;
    }
  }
  if (tx_type != TRON_TX_UNVERIFIED) {
    /* The parsed owner account is the one spending — it must be ours. */
    char derived_addr[TRON_ADDRESS_MAX_LEN];
    char owner_addr[TRON_ADDRESS_MAX_LEN];
    if (!tron_getAddress(node->public_key, derived_addr,
                         sizeof(derived_addr)) ||
        !tron_addressFromBytes(parsed.owner, owner_addr, sizeof(owner_addr)) ||
        strcmp(derived_addr, owner_addr) != 0) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_Other,
                      _("TX owner does not match derived key"));
      layoutHome();
      return;
    }

    bool confirmed = tron_confirmParsed(&parsed, token);

    if (confirmed && parsed.has_fee_limit) {
      /* fee_limit caps smart-contract energy only: bandwidth is charged on
       * top, and native transfers, staking and votes ignore it. */
      char fee_str[32];
      tron_formatAmount(fee_str, sizeof(fee_str), parsed.fee_limit);
      confirmed =
          confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "TRON",
                  "Energy fee limit %s\n%s", fee_str,
                  tx_type == TRON_TX_TRANSFER ? "Not used by TRX transfers"
                  : trc20                     ? "Bandwidth fees are extra"
                                              : "Not used by this transaction");
    }

    if (confirmed && parsed.memo_len > 0) {
      /* raw_data.data is signed verbatim. A byte count or one unpaged screen
       * hides a long memo's tail; confirm_bytes pages and escapes every byte.
       */
      confirmed = confirm_bytes(ButtonRequestType_ButtonRequest_ConfirmMemo,
                                "Memo", parsed.memo, parsed.memo_len);
    }

    if (!confirmed) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
      layoutHome();
      return;
    }
  }

  // Sign the transaction with secp256k1
  if (!tron_signTx(node, msg, resp)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("TRON signing failed"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_TronSignedTx, resp);
  layoutHome();
}

void fsm_msgTronSignMessage(TronSignMessage* msg) {
  RESP_INIT(TronMessageSignature);

  CHECK_INITIALIZED

  CHECK_PIN

  // Validate path: m/44'/195'/...
  if (msg->address_n_count < 3 || msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 195)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TRON path (expected m/44'/195'/...)"));
    layoutHome();
    return;
  }

  CHECK_PARAM(msg->has_message && msg->message.size > 0 &&
                  msg->message.size <= sizeof(msg->message.bytes),
              _("Invalid TRON message"));
  if (!confirm_bytes(ButtonRequestType_ButtonRequest_ProtectCall,
                     _("Sign TRON Message"), msg->message.bytes,
                     msg->message.size)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  if (!tron_message_sign(node, msg, resp)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other,
                    _("TRON message signing failed"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_TronMessageSignature, resp);
  layoutHome();
}

void fsm_msgTronVerifyMessage(const TronVerifyMessage* msg) {
  CHECK_PARAM(msg->has_address, _("No address provided"));
  CHECK_PARAM(msg->has_message && msg->message.size > 0 &&
                  msg->message.size <= sizeof(msg->message.bytes),
              _("Invalid TRON message"));
  CHECK_PARAM(msg->has_signature, _("No signature provided"));

  if (tron_message_verify(msg) != 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Invalid signature"));
    return;
  }

  if (!confirm_address(_("Confirm Signer"), msg->address)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (!confirm_bytes(ButtonRequestType_ButtonRequest_Other,
                     _("Message Verified"), msg->message.bytes,
                     msg->message.size)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
  fsm_sendSuccess(_("Message verified"));
  layoutHome();
}
void fsm_msgTronSignTypedHash(const TronSignTypedHash* msg) {
  RESP_INIT(TronTypedDataSignature);

  CHECK_INITIALIZED

  CHECK_PIN

  // Validate path: m/44'/195'/...
  if (msg->address_n_count < 3 || msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 195)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TRON path (expected m/44'/195'/...)"));
    layoutHome();
    return;
  }

  if (msg->domain_separator_hash.size != 32 ||
      (msg->has_message_hash && msg->message_hash.size != 32)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TIP-712 hash length"));
    layoutHome();
    return;
  }

  /* Only hashes arrive, so this is blind: gate before any key derivation. */
  if (!tron_typed_hash_policy_allows(storage_isPolicyEnabled("AdvancedMode"))) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Enable AdvancedMode to blind-sign typed hashes"));
    layoutHome();
    return;
  }

  if (!confirm(ButtonRequestType_ButtonRequest_Other, "TIP-712 Blind Sign",
               "Cannot verify these hashes. Trust the host?")) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  // Derive Base58Check address for confirm dialog + response.
  char address[TRON_ADDRESS_MAX_LEN];
  if (!tron_getAddress(node->public_key, address, sizeof(address))) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("Address derivation failed"));
    layoutHome();
    return;
  }

  if (!confirm(ButtonRequestType_ButtonRequest_Other, "Verify Address",
               "Confirm address: %s", address)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  // Show domain separator hash as 64-char hex.
  char str[64 + 1];
  for (int ctr = 0; ctr < 64 / 2; ctr++) {
    snprintf(&str[2 * ctr], 3, "%02x", msg->domain_separator_hash.bytes[ctr]);
  }
  if (!confirm(ButtonRequestType_ButtonRequest_Other, "TIP-712 domain",
               "Confirm hash digest: %s", str)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (msg->has_message_hash) {
    for (int ctr = 0; ctr < 64 / 2; ctr++) {
      snprintf(&str[2 * ctr], 3, "%02x", msg->message_hash.bytes[ctr]);
    }
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "TIP-712 message",
                 "Confirm hash digest: %s", str)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  } else {
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "TIP-712 message",
                 "Confirm: No message")) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  if (!tron_typed_hash_sign(node, msg, resp)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other,
                    _("TIP-712 hash signing failed"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_TronTypedDataSignature, resp);
  layoutHome();
}
