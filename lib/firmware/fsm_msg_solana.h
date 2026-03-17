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

/* Helper: Raw base58 encode (no checksum) for Solana pubkeys/addresses.
 * Uses b58enc() from trezor-crypto, which is the raw base58 encoder.
 * Solana addresses are raw base58-encoded 32-byte Ed25519 public keys. */
static bool solana_base58_encode(const uint8_t *data, size_t data_len,
                                  char *out, size_t *out_len) {
    return b58enc(out, out_len, data, data_len);
}

/* Helper: Base58-encode a 32-byte pubkey for display (truncated) */
static void solana_pubkeyToShort(const uint8_t key[SOL_PUBKEY_SIZE],
                                 char *out, size_t out_len) {
    char full[45];
    size_t full_len = sizeof(full);
    if (solana_base58_encode(key, SOL_PUBKEY_SIZE, full, &full_len)) {
        /* Truncate: first 4 chars ... last 4 chars */
        size_t slen = strlen(full);
        if (slen > 9 && out_len > 10) {
            snprintf(out, out_len, "%.4s...%.4s", full, full + slen - 4);
        } else {
            strncpy(out, full, out_len - 1);
            out[out_len - 1] = '\0';
        }
    } else {
        /* Fallback to hex if base58 fails */
        snprintf(out, out_len,
                 "%02x%02x...%02x%02x",
                 key[0], key[1], key[30], key[31]);
    }
}

/* Confirm a single parsed instruction */
static bool solana_confirmInstruction(const SolanaParsedInstruction *pi,
                                      const SolanaSignTx *msg,
                                      uint8_t idx, uint8_t total) {
    char title[32];
    snprintf(title, sizeof(title), "Instr %d/%d", idx + 1, total);

    switch (pi->type) {
        case SOL_INSTR_SYSTEM_TRANSFER: {
            char amount_str[32];
            solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
            char to_str[32];
            solana_pubkeyToShort(pi->to, to_str, sizeof(to_str));
            return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                          title, "Send %s to %s?", amount_str, to_str);
        }

        case SOL_INSTR_SYSTEM_CREATE_ACCOUNT: {
            char amount_str[32];
            solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
            return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                          title, "Create account with %s?", amount_str);
        }

        case SOL_INSTR_TOKEN_TRANSFER:
        case SOL_INSTR_TOKEN_TRANSFER_CHECKED: {
            char to_str[32];
            solana_pubkeyToShort(pi->to, to_str, sizeof(to_str));

            /* Try to find token info from host-provided metadata */
            const SolanaTokenInfo *ti = NULL;
            if (pi->has_mint) {
                ti = solana_findTokenInfo(msg, pi->mint);
            }

            if (ti && ti->has_symbol && ti->has_decimals) {
                char amount_str[48];
                solana_formatTokenAmount(amount_str, sizeof(amount_str),
                                         pi->amount, ti->symbol,
                                         (uint8_t)ti->decimals);
                return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                              title, "Send %s to %s?", amount_str, to_str);
            } else {
                char amount_str[32];
                snprintf(amount_str, sizeof(amount_str), "%llu tokens",
                         (unsigned long long)pi->amount);
                return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                              title, "Send %s to %s?", amount_str, to_str);
            }
        }

        case SOL_INSTR_TOKEN_APPROVE: {
            char to_str[32];
            solana_pubkeyToShort(pi->to, to_str, sizeof(to_str));
            return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                          title, "Approve %llu tokens to %s?",
                          (unsigned long long)pi->amount, to_str);
        }

        case SOL_INSTR_STAKE_DELEGATE: {
            return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                          title, "Delegate stake?");
        }

        case SOL_INSTR_STAKE_WITHDRAW: {
            char amount_str[32];
            solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
            return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                          title, "Withdraw %s from stake?", amount_str);
        }

        case SOL_INSTR_UNKNOWN:
        default: {
            char prog_str[32];
            solana_pubkeyToShort(pi->program_id, prog_str, sizeof(prog_str));
            return confirm(ButtonRequestType_ButtonRequest_SignTx,
                          title,
                          "Unknown instruction to program %s. "
                          "Cannot verify contents.", prog_str);
        }
    }
}

void fsm_msgSolanaGetAddress(const SolanaGetAddress *msg) {
    RESP_INIT(SolanaAddress);

    CHECK_INITIALIZED
    CHECK_PIN

    HDNode *node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                      msg->address_n_count, NULL);
    if (!node) return;
    hdnode_fill_public_key(node);

    /* Solana address = raw Base58 of the 32-byte Ed25519 public key.
     * node->public_key is 33 bytes (0x00 prefix + 32 bytes for Ed25519).
     * Use b58enc() for raw base58 encoding (no checksum). */
    char address[45];
    size_t addr_len = sizeof(address);
    if (solana_base58_encode(node->public_key + 1, SOL_PUBKEY_SIZE,
                             address, &addr_len)) {
        resp->has_address = true;
        strncpy(resp->address, address, sizeof(resp->address) - 1);
    } else {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_Other,
                        _("Address encoding failed"));
        layoutHome();
        return;
    }

    if (msg->has_show_display && msg->show_display) {
        if (!confirm_ethereum_address("Solana", resp->address)) {
            memzero(node, sizeof(*node));
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            _("Show address cancelled"));
            layoutHome();
            return;
        }
    }

    memzero(node, sizeof(*node));
    msg_write(MessageType_MessageType_SolanaAddress, resp);
    layoutHome();
}

void fsm_msgSolanaSignTx(SolanaSignTx *msg) {
    RESP_INIT(SolanaSignedTx);

    CHECK_INITIALIZED
    CHECK_PIN

    if (!msg->has_raw_tx || msg->raw_tx.size == 0) {
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Missing raw_tx"));
        layoutHome();
        return;
    }

    HDNode *node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                      msg->address_n_count, NULL);
    if (!node) return;
    hdnode_fill_public_key(node);

    /* Parse transaction for per-instruction confirmation */
    SolanaParsedTx parsed;
    bool parse_ok = solana_parseTx(msg->raw_tx.bytes, msg->raw_tx.size,
                                   &parsed);

    if (parse_ok && parsed.num_instructions > 0) {
        /* Per-instruction confirmation */
        uint8_t unknown_count = 0;
        for (uint8_t i = 0; i < parsed.num_instructions; i++) {
            if (parsed.instructions[i].type == SOL_INSTR_UNKNOWN) {
                unknown_count++;
            }
        }

        for (uint8_t i = 0; i < parsed.num_instructions; i++) {
            if (!solana_confirmInstruction(&parsed.instructions[i], msg,
                                           i, parsed.num_instructions)) {
                memzero(node, sizeof(*node));
                fsm_sendFailure(FailureType_Failure_ActionCancelled,
                                _("Signing cancelled"));
                layoutHome();
                return;
            }
        }

        /* Summary warning if there were unknown instructions */
        if (unknown_count > 0) {
            if (!confirm(ButtonRequestType_ButtonRequest_SignTx,
                         "Warning",
                         "%d of %d instructions could not be verified.",
                         unknown_count, parsed.num_instructions)) {
                memzero(node, sizeof(*node));
                fsm_sendFailure(FailureType_Failure_ActionCancelled,
                                _("Signing cancelled"));
                layoutHome();
                return;
            }
        }
    } else {
        /* Parse failed — blind sign with warning */
        if (!confirm(ButtonRequestType_ButtonRequest_SignTx,
                     "Blind Sign",
                     "Sign unverified Solana transaction? "
                     "The device cannot parse the contents.")) {
            memzero(node, sizeof(*node));
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            _("Signing cancelled"));
            layoutHome();
            return;
        }
    }

    /* Final confirmation */
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx,
                 "Solana",
                 "Sign this Solana transaction?")) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        _("Signing cancelled"));
        layoutHome();
        return;
    }

    if (!solana_signTx(node, msg, resp)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_Other,
                        _("Signing failed"));
        layoutHome();
        return;
    }

    memzero(node, sizeof(*node));
    msg_write(MessageType_MessageType_SolanaSignedTx, resp);
    layoutHome();
}

void fsm_msgSolanaSignMessage(const SolanaSignMessage *msg) {
    RESP_INIT(SolanaMessageSignature);

    CHECK_INITIALIZED
    CHECK_PIN

    if (!msg->has_message || msg->message.size == 0) {
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Missing message"));
        layoutHome();
        return;
    }

    HDNode *node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                      msg->address_n_count, NULL);
    if (!node) return;
    hdnode_fill_public_key(node);

    if (msg->has_show_display && msg->show_display) {
        if (!confirm(ButtonRequestType_ButtonRequest_SignMessage,
                     "Sign Message",
                     "Sign this Solana message (%u bytes)?",
                     (unsigned)msg->message.size)) {
            memzero(node, sizeof(*node));
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            _("Signing cancelled"));
            layoutHome();
            return;
        }
    }

    /* Ed25519 sign */
    uint8_t sig[SOL_SIG_SIZE];
    ed25519_sign(msg->message.bytes, msg->message.size,
                 node->private_key, node->public_key + 1, sig);

    resp->has_signature = true;
    resp->signature.size = SOL_SIG_SIZE;
    memcpy(resp->signature.bytes, sig, SOL_SIG_SIZE);

    resp->has_public_key = true;
    resp->public_key.size = SOL_PUBKEY_SIZE;
    memcpy(resp->public_key.bytes, node->public_key + 1, SOL_PUBKEY_SIZE);

    memzero(node, sizeof(*node));
    msg_write(MessageType_MessageType_SolanaMessageSignature, resp);
    layoutHome();
}
