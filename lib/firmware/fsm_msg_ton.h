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

void fsm_msgTonGetAddress(const TonGetAddress *msg) {
    RESP_INIT(TonAddress);

    CHECK_INITIALIZED
    CHECK_PIN

    HDNode *node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                      msg->address_n_count, NULL);
    if (!node) return;
    hdnode_fill_public_key(node);

    /* TON address derivation:
     * 1. Ed25519 public key → StateInit(v4r2_code, data(pubkey))
     * 2. SHA256(StateInit cell) → address hash
     * For now, return the raw public key hex as address placeholder.
     * Full v4r2 address derivation is done in the vault adapter. */

    /* We store the user-friendly address in resp->address.
     * The actual v4r2 address computation is complex (requires code cell hash).
     * The device stores just the raw form and the host provides the
     * user-friendly encoding. For GetAddress, we derive on-device. */

    /* TODO: full on-device v4r2 address derivation.
     * For now, just return a raw workchain:hash representation. */
    char raw_addr[70];
    uint8_t pubkey_hash[32];
    sha256_Raw(node->public_key + 1, 32, pubkey_hash);

    int8_t wc = msg->has_workchain ? (int8_t)msg->workchain : 0;
    snprintf(raw_addr, sizeof(raw_addr),
             "%d:%02x%02x%02x%02x%02x%02x%02x%02x"
             "%02x%02x%02x%02x%02x%02x%02x%02x"
             "%02x%02x%02x%02x%02x%02x%02x%02x"
             "%02x%02x%02x%02x%02x%02x%02x%02x",
             wc,
             pubkey_hash[0], pubkey_hash[1], pubkey_hash[2], pubkey_hash[3],
             pubkey_hash[4], pubkey_hash[5], pubkey_hash[6], pubkey_hash[7],
             pubkey_hash[8], pubkey_hash[9], pubkey_hash[10], pubkey_hash[11],
             pubkey_hash[12], pubkey_hash[13], pubkey_hash[14], pubkey_hash[15],
             pubkey_hash[16], pubkey_hash[17], pubkey_hash[18], pubkey_hash[19],
             pubkey_hash[20], pubkey_hash[21], pubkey_hash[22], pubkey_hash[23],
             pubkey_hash[24], pubkey_hash[25], pubkey_hash[26], pubkey_hash[27],
             pubkey_hash[28], pubkey_hash[29], pubkey_hash[30], pubkey_hash[31]);

    resp->has_raw_address = true;
    strncpy(resp->raw_address, raw_addr, sizeof(resp->raw_address) - 1);

    if (msg->has_show_display && msg->show_display) {
        if (!confirm_ethereum_address("TON", resp->raw_address)) {
            memzero(node, sizeof(*node));
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            _("Show address cancelled"));
            layoutHome();
            return;
        }
    }

    memzero(node, sizeof(*node));
    msg_write(MessageType_MessageType_TonAddress, resp);
    layoutHome();
}

void fsm_msgTonSignTx(TonSignTx *msg) {
    RESP_INIT(TonSignedTx);

    CHECK_INITIALIZED
    CHECK_PIN

    HDNode *node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                      msg->address_n_count, NULL);
    if (!node) return;
    hdnode_fill_public_key(node);

    bool is_structured = msg->has_destination && msg->has_ton_amount &&
                         msg->has_seqno;
    bool is_legacy = msg->has_raw_tx && msg->raw_tx.size > 0;

    if (!is_structured && !is_legacy) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Must provide destination+amount+seqno or raw_tx"));
        layoutHome();
        return;
    }

    if (is_legacy && !is_structured) {
        /* ---- LEGACY BLIND-SIGN MODE ---- */
        if (!confirm(ButtonRequestType_ButtonRequest_SignTx,
                     "Blind Sign",
                     "Sign unverified TON transaction? "
                     "The device cannot verify the contents.")) {
            memzero(node, sizeof(*node));
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            _("Signing cancelled"));
            layoutHome();
            return;
        }

        /* Show unverified display hints if provided */
        if (msg->has_destination && msg->has_ton_amount) {
            char amount_str[32];
            ton_formatAmount(amount_str, sizeof(amount_str), msg->ton_amount);
            if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                         "Unverified",
                         "Send %s to %s? (UNVERIFIED)",
                         amount_str, msg->destination)) {
                memzero(node, sizeof(*node));
                fsm_sendFailure(FailureType_Failure_ActionCancelled,
                                _("Signing cancelled"));
                layoutHome();
                return;
            }
        }
    } else {
        /* ---- STRUCTURED MODE ---- */
        char amount_str[32];
        ton_formatAmount(amount_str, sizeof(amount_str), msg->ton_amount);

        /* Truncate destination for display */
        char dest_short[20];
        size_t dlen = strlen(msg->destination);
        if (dlen > 16) {
            memcpy(dest_short, msg->destination, 6);
            memcpy(dest_short + 6, "...", 3);
            memcpy(dest_short + 9, msg->destination + dlen - 6, 6);
            dest_short[15] = '\0';
        } else {
            strncpy(dest_short, msg->destination, sizeof(dest_short) - 1);
            dest_short[sizeof(dest_short) - 1] = '\0';
        }

        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                     "Send TON",
                     "Send %s to %s?", amount_str, dest_short)) {
            memzero(node, sizeof(*node));
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            _("Signing cancelled"));
            layoutHome();
            return;
        }

        /* Show comment if present */
        if (msg->has_comment && msg->comment[0] != '\0') {
            if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                         "Comment",
                         "Memo: %.60s%s", msg->comment,
                         strlen(msg->comment) > 60 ? "..." : "")) {
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
                 "TON",
                 "Sign this TON transaction?")) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        _("Signing cancelled"));
        layoutHome();
        return;
    }

    if (!ton_signTx(node, msg, resp)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_Other,
                        _("Signing failed"));
        layoutHome();
        return;
    }

    memzero(node, sizeof(*node));
    msg_write(MessageType_MessageType_TonSignedTx, resp);
    layoutHome();
}
