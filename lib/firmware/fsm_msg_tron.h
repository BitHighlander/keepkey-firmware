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

void fsm_msgTronGetAddress(const TronGetAddress *msg) {
  RESP_INIT(TronAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  // Validate path: m/44'/195'/...
  if (msg->address_n_count < 3 ||
      msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 195)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TRON path (expected m/44'/195'/...)"));
    layoutHome();
    return;
  }

  // Derive node using secp256k1 curve
  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
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

void fsm_msgTronSignTx(TronSignTx *msg) {
  RESP_INIT(TronSignedTx);

  CHECK_INITIALIZED

  CHECK_PIN

  // Validate path: m/44'/195'/...
  if (msg->address_n_count < 3 ||
      msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 195)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TRON path (expected m/44'/195'/...)"));
    layoutHome();
    return;
  }

  // Derive node using secp256k1 curve
  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  if (!msg->has_raw_data || msg->raw_data.size == 0) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Missing transaction data"));
    layoutHome();
    return;
  }

  // Try to parse a TransferContract from the signed payload so the device
  // can show verified transfer details instead of host-asserted fields.
  TronParsedTransfer parsed;
  if (tron_parseTransfer(msg->raw_data.bytes, msg->raw_data.size, &parsed)) {
    // Simple TRX transfer — show on-device-verified details
    char to_addr[TRON_ADDRESS_MAX_LEN];
    if (!base58_encode_check(parsed.to_address, 21, HASHER_SHA2D,
                             to_addr, sizeof(to_addr))) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_Other, _("Bad to_address in TX"));
      layoutHome();
      return;
    }

    char amount_str[32];
    tron_formatAmount(amount_str, sizeof(amount_str), (uint64_t)parsed.amount);

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "TRON Transfer", "Send %s to\n%s?",
                 amount_str, to_addr)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
      layoutHome();
      return;
    }
  } else {
    // Token / contract / complex TX — blind sign with explicit warning
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Blind Signature",
                 "Cannot verify TX details on device. "
                 "Sign only if you trust the sending app.")) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
      layoutHome();
      return;
    }
  }

  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Confirm",
               "Sign this TRON transaction?")) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
    layoutHome();
    return;
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
