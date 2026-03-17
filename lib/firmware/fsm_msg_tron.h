/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2025 KeepKey
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

#include "tron_tokens.h"

void fsm_msgTronGetAddress(const TronGetAddress *msg) {
    RESP_INIT(TronAddress);

    CHECK_INITIALIZED
    CHECK_PIN

    HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                      msg->address_n_count, NULL);
    if (!node) return;
    hdnode_fill_public_key(node);

    if (!tron_getAddress(node->public_key, resp->address)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_Other,
                        _("Address derivation failed"));
        layoutHome();
        return;
    }
    resp->has_address = true;

    if (msg->has_show_display && msg->show_display) {
        const CoinType *coin = fsm_getCoin(true, "Tron");
        char node_str[NODE_STRING_LENGTH];
        if (!(bip32_node_to_string(node_str, sizeof(node_str), coin,
                                   msg->address_n, msg->address_n_count,
                                   /*whole_account=*/false,
                                   /*show_addridx=*/false)) &&
            !bip32_path_to_string(node_str, sizeof(node_str),
                                  msg->address_n, msg->address_n_count)) {
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

    HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                      msg->address_n_count, NULL);
    if (!node) return;
    hdnode_fill_public_key(node);

    bool is_structured = msg->has_transfer || msg->has_trigger_smart;
    bool is_legacy = msg->has_raw_data && msg->raw_data.size > 0;

    if (!is_structured && !is_legacy) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Must provide transfer, trigger_smart, or raw_data"));
        layoutHome();
        return;
    }

    if (is_legacy && !is_structured) {
        /* ---- LEGACY BLIND-SIGN MODE ---- */
        /* Show warning that raw bytes are being signed */
        if (!confirm(ButtonRequestType_ButtonRequest_SignTx,
                     "Blind Sign",
                     "Sign unverified TRON transaction? "
                     "The device cannot verify the contents.")) {
            memzero(node, sizeof(*node));
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            _("Signing cancelled"));
            layoutHome();
            return;
        }

        /* Show amount/address if host provided them (display-only, unverified) */
        if (msg->has_to_address && msg->has_amount) {
            char amount_str[32];
            tron_formatAmount(amount_str, sizeof(amount_str), msg->amount);
            if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                         "Unverified",
                         "Send %s to %s? (UNVERIFIED)", amount_str,
                         msg->to_address)) {
                memzero(node, sizeof(*node));
                fsm_sendFailure(FailureType_Failure_ActionCancelled,
                                _("Signing cancelled"));
                layoutHome();
                return;
            }
        }
    } else {
        /* ---- STRUCTURED RECONSTRUCT-THEN-SIGN MODE ---- */

        /* Validate required block reference fields */
        if (!msg->has_ref_block_bytes || msg->ref_block_bytes.size != 2 ||
            !msg->has_ref_block_hash || msg->ref_block_hash.size != 8 ||
            !msg->has_expiration) {
            memzero(node, sizeof(*node));
            fsm_sendFailure(FailureType_Failure_SyntaxError,
                _("Structured mode requires ref_block_bytes, "
                  "ref_block_hash, expiration"));
            layoutHome();
            return;
        }

        /* Show memo/data if present (max 256 bytes, matching Trezor) */
        if (msg->has_data && msg->data.size > 0) {
            if (msg->data.size > 256) {
                memzero(node, sizeof(*node));
                fsm_sendFailure(FailureType_Failure_SyntaxError,
                                _("Data/memo field too long (max 256)"));
                layoutHome();
                return;
            }
            /* Display as hex since memo may not be valid UTF-8 */
            char memo_hex[64];
            size_t show_len = msg->data.size < 24 ? msg->data.size : 24;
            for (size_t i = 0; i < show_len; i++) {
                snprintf(memo_hex + i * 2, 3, "%02x", msg->data.bytes[i]);
            }
            if (msg->data.size > 24) {
                snprintf(memo_hex + show_len * 2,
                         sizeof(memo_hex) - show_len * 2, "...");
            }
            if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                         "Memo",
                         "Note: %s (%zu bytes)", memo_hex,
                         msg->data.size)) {
                memzero(node, sizeof(*node));
                fsm_sendFailure(FailureType_Failure_ActionCancelled,
                                _("Signing cancelled"));
                layoutHome();
                return;
            }
        }

        if (msg->has_transfer) {
            /* HIGH-3: Validate to_address BEFORE displaying to user */
            uint8_t validate_raw[TRON_ADDRESS_SIZE];
            if (!tron_decodeAddress(msg->transfer.to_address, validate_raw)) {
                memzero(node, sizeof(*node));
                fsm_sendFailure(FailureType_Failure_SyntaxError,
                                _("Invalid TRON recipient address"));
                layoutHome();
                return;
            }

            /* TRX Transfer — show verified amount and destination */
            char amount_str[32];
            tron_formatAmount(amount_str, sizeof(amount_str),
                              msg->transfer.amount);

            if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                         "Send TRX",
                         "Send %s to %s?", amount_str,
                         msg->transfer.to_address)) {
                memzero(node, sizeof(*node));
                fsm_sendFailure(FailureType_Failure_ActionCancelled,
                                _("Signing cancelled"));
                layoutHome();
                return;
            }
        } else if (msg->has_trigger_smart) {
            /* Validate contract_address BEFORE any display */
            uint8_t contract_validate_raw[TRON_ADDRESS_SIZE];
            if (!tron_decodeAddress(msg->trigger_smart.contract_address,
                                    contract_validate_raw)) {
                memzero(node, sizeof(*node));
                fsm_sendFailure(FailureType_Failure_SyntaxError,
                                _("Invalid TRON contract address"));
                layoutHome();
                return;
            }

            /* Smart contract call — try to decode TRC-20 transfer */
            uint8_t trc20_to[TRON_ADDRESS_SIZE];
            uint8_t trc20_amount[32];

            if (msg->trigger_smart.data.size >= 68 &&
                tron_decodeTRC20Transfer(msg->trigger_smart.data.bytes,
                                         msg->trigger_smart.data.size,
                                         trc20_to, trc20_amount)) {
                /* Known TRC-20 transfer — look up token */
                const TronToken *token = tron_token_by_address(
                    msg->trigger_smart.contract_address);

                char to_addr[MAX_TRON_ADDR_SIZE];
                /* Encode the decoded address back to Base58 for display */
                if (base58_encode_check(trc20_to, TRON_ADDRESS_SIZE,
                                        HASHER_SHA2D, to_addr,
                                        sizeof(to_addr)) == 0) {
                    memzero(node, sizeof(*node));
                    fsm_sendFailure(FailureType_Failure_Other,
                                    _("Failed to encode recipient"));
                    layoutHome();
                    return;
                }

                if (token) {
                    char token_amount[64];
                    tron_formatTokenAmount(token_amount, sizeof(token_amount),
                                           trc20_amount, token);
                    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                                 "Send Token",
                                 "Send %s to %s?", token_amount, to_addr)) {
                        memzero(node, sizeof(*node));
                        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                                        _("Signing cancelled"));
                        layoutHome();
                        return;
                    }
                } else {
                    /* Unknown TRC-20 token */
                    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                                 "Unknown Token",
                                 "Transfer unknown token at %s to %s?",
                                 msg->trigger_smart.contract_address,
                                 to_addr)) {
                        memzero(node, sizeof(*node));
                        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                                        _("Signing cancelled"));
                        layoutHome();
                        return;
                    }
                }
            } else {
                /* Unknown smart contract call — show contract address */
                if (!confirm(ButtonRequestType_ButtonRequest_SignTx,
                             "Smart Contract",
                             "Call contract %s? "
                             "Cannot verify call data.",
                             msg->trigger_smart.contract_address)) {
                    memzero(node, sizeof(*node));
                    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                                    _("Signing cancelled"));
                    layoutHome();
                    return;
                }
            }

            /* Show call_value if nonzero */
            if (msg->trigger_smart.has_call_value &&
                msg->trigger_smart.call_value > 0) {
                char val_str[32];
                tron_formatAmount(val_str, sizeof(val_str),
                                  msg->trigger_smart.call_value);
                if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                             "Call Value",
                             "Also sending %s with call?", val_str)) {
                    memzero(node, sizeof(*node));
                    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                                    _("Signing cancelled"));
                    layoutHome();
                    return;
                }
            }
        }

        /* Show fee limit if present */
        if (msg->has_fee_limit && msg->fee_limit > 0) {
            char fee_str[32];
            tron_formatAmount(fee_str, sizeof(fee_str), msg->fee_limit);
            if (!confirm(ButtonRequestType_ButtonRequest_SignTx,
                         "Fee Limit",
                         "Maximum fee: %s?", fee_str)) {
                memzero(node, sizeof(*node));
                fsm_sendFailure(FailureType_Failure_ActionCancelled,
                                _("Signing cancelled"));
                layoutHome();
                return;
            }
        }
    }

    /* Final confirmation */
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx,
                 "TRON",
                 "Sign this TRON transaction?")) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        _("Signing cancelled"));
        layoutHome();
        return;
    }

    if (!tron_signTx(node, msg, resp)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_Other,
                        _("Signing failed"));
        layoutHome();
        return;
    }

    memzero(node, sizeof(*node));
    msg_write(MessageType_MessageType_TronSignedTx, resp);
    layoutHome();
}
